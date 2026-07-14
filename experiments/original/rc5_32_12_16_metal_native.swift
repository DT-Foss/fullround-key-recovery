import Foundation
import CoreFoundation
import Metal

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

struct SearchParams {
    uint plaintext[4];
    uint target[4];
    uint control[4];
    uint key1;
    uint key2;
    uint key3;
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

inline uint rol32(uint value, uint shift) {
    shift &= 31u;
    return (value << shift) | (value >> ((32u - shift) & 31u));
}

constant uint RC5_INITIAL_SUBKEYS[26] = {
    0xb7e15163u, 0x5618cb1cu, 0xf45044d5u, 0x9287be8eu,
    0x30bf3847u, 0xcef6b200u, 0x6d2e2bb9u, 0x0b65a572u,
    0xa99d1f2bu, 0x47d498e4u, 0xe60c129du, 0x84438c56u,
    0x227b060fu, 0xc0b27fc8u, 0x5ee9f981u, 0xfd21733au,
    0x9b58ecf3u, 0x399066acu, 0xd7c7e065u, 0x75ff5a1eu,
    0x1436d3d7u, 0xb26e4d90u, 0x50a5c749u, 0xeedd4102u,
    0x8d14babbu, 0x2b4c3474u,
};

inline void rc5_32_12_16_expand_key(
    thread uint *subkeys,
    uint candidate,
    constant SearchParams &params
) {
    thread uint key_words[4] = {candidate, params.key1, params.key2, params.key3};
    for (uint index = 0u; index < 26u; ++index) {
        subkeys[index] = RC5_INITIAL_SUBKEYS[index];
    }
    uint index_s = 0u;
    uint index_l = 0u;
    uint accumulator_a = 0u;
    uint accumulator_b = 0u;
    for (uint mix = 0u; mix < 78u; ++mix) {
        accumulator_a = rol32(
            subkeys[index_s] + accumulator_a + accumulator_b, 3u
        );
        subkeys[index_s] = accumulator_a;
        accumulator_b = rol32(
            key_words[index_l] + accumulator_a + accumulator_b,
            accumulator_a + accumulator_b
        );
        key_words[index_l] = accumulator_b;
        index_s = index_s == 25u ? 0u : index_s + 1u;
        index_l = (index_l + 1u) & 3u;
    }
}

inline uint2 rc5_32_12_16_encrypt(uint2 state, thread const uint *subkeys) {
    uint value_a = state.x + subkeys[0];
    uint value_b = state.y + subkeys[1];
    for (uint round = 1u; round <= 12u; ++round) {
        value_a = rol32(value_a ^ value_b, value_b) + subkeys[2u * round];
        value_b = rol32(value_b ^ value_a, value_a) + subkeys[2u * round + 1u];
    }
    return uint2(value_a, value_b);
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

kernel void rc5_32_12_16_filter(
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
    thread uint subkeys[26];
    rc5_32_12_16_expand_key(subkeys, candidate, params);
    bool factual_match = true;
    bool control_match = true;
    for (uint block = 0u; block < 2u; ++block) {
        if (!factual_match && !control_match) {
            break;
        }
        const uint offset = block * 2u;
        const uint2 output = rc5_32_12_16_encrypt(
            uint2(params.plaintext[offset], params.plaintext[offset + 1u]),
            subkeys
        );
        factual_match = factual_match
            && output.x == params.target[offset]
            && output.y == params.target[offset + 1u];
        control_match = control_match
            && output.x == params.control[offset]
            && output.y == params.control[offset + 1u];
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

kernel void rc5_32_12_16_blocks(
    constant SearchParams &params [[buffer(0)]],
    device uint *output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    const uint candidate = params.first_candidate + gid;
    thread uint subkeys[26];
    rc5_32_12_16_expand_key(subkeys, candidate, params);
    for (uint block = 0u; block < 2u; ++block) {
        const uint offset = block * 2u;
        const uint2 ciphertext = rc5_32_12_16_encrypt(
            uint2(params.plaintext[offset], params.plaintext[offset + 1u]),
            subkeys
        );
        output[gid * 4u + offset] = ciphertext.x;
        output[gid * 4u + offset + 1u] = ciphertext.y;
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
    let key1: UInt32
    let key2: UInt32
    let key3: UInt32
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
    first: UInt32,
    count: UInt32,
    capacity: UInt32
) -> [UInt32] {
    return config.plaintext
        + config.target
        + config.control
        + [config.key1, config.key2, config.key3, first, count, capacity]
}

private final class MetalRC5321216Host {
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
        guard let filter = library.makeFunction(name: "rc5_32_12_16_filter"),
              let blocks = library.makeFunction(name: "rc5_32_12_16_blocks"),
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
    let host = try MetalRC5321216Host()
    try emit([
        "op": "ready",
        "version": "rc5-32-12-16-metal-native-v1",
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
                plaintext: try word32Array(
                    request["plaintext"], field: "plaintext", count: 4
                ),
                target: try word32Array(request["target"], field: "target", count: 4),
                control: try word32Array(
                    request["control"], field: "control", count: 4
                ),
                key1: try uint32(request["key1"], field: "key1"),
                key2: try uint32(request["key2"], field: "key2"),
                key3: try uint32(request["key3"], field: "key3")
            )
            configuration = config
            try emit(["op": "configured", "plaintext_blocks": 2, "filter_words": 4])
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
