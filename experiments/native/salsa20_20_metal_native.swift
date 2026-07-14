import Foundation
import CoreFoundation
import Metal

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

struct SearchParams {
    uint target[16];
    uint control[16];
    uint key_words_1_to_7[7];
    uint nonce[2];
    uint counter[2];
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

inline uint rol32(uint value, uint shift) {
    return (value << shift) | (value >> (32u - shift));
}

inline void salsa20_quarterround(
    thread uint *x, uint a, uint b, uint c, uint d
) {
    x[b] ^= rol32(x[a] + x[d], 7u);
    x[c] ^= rol32(x[b] + x[a], 9u);
    x[d] ^= rol32(x[c] + x[b], 13u);
    x[a] ^= rol32(x[d] + x[c], 18u);
}

inline void salsa20_20_block(
    thread uint *output,
    uint candidate,
    constant SearchParams &params
) {
    thread uint input[16] = {
        0x61707865u,
        candidate,
        params.key_words_1_to_7[0],
        params.key_words_1_to_7[1],
        params.key_words_1_to_7[2],
        0x3320646eu,
        params.nonce[0],
        params.nonce[1],
        params.counter[0],
        params.counter[1],
        0x79622d32u,
        params.key_words_1_to_7[3],
        params.key_words_1_to_7[4],
        params.key_words_1_to_7[5],
        params.key_words_1_to_7[6],
        0x6b206574u,
    };
    for (uint index = 0u; index < 16u; ++index) {
        output[index] = input[index];
    }
    for (uint double_round = 0u; double_round < 10u; ++double_round) {
        salsa20_quarterround(output, 0u, 4u, 8u, 12u);
        salsa20_quarterround(output, 5u, 9u, 13u, 1u);
        salsa20_quarterround(output, 10u, 14u, 2u, 6u);
        salsa20_quarterround(output, 15u, 3u, 7u, 11u);
        salsa20_quarterround(output, 0u, 1u, 2u, 3u);
        salsa20_quarterround(output, 5u, 6u, 7u, 4u);
        salsa20_quarterround(output, 10u, 11u, 8u, 9u);
        salsa20_quarterround(output, 15u, 12u, 13u, 14u);
    }
    for (uint index = 0u; index < 16u; ++index) {
        output[index] += input[index];
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

kernel void salsa20_20_filter(
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
    thread uint output[16];
    salsa20_20_block(output, candidate, params);
    bool factual_match = true;
    bool control_match = true;
    for (uint index = 0u; index < 16u; ++index) {
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

kernel void salsa20_20_blocks(
    constant SearchParams &params [[buffer(0)]],
    device uint *outputs [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    thread uint output[16];
    salsa20_20_block(output, params.first_candidate + gid, params);
    for (uint index = 0u; index < 16u; ++index) {
        outputs[gid * 16u + index] = output[index];
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
    let keyWords1To7: [UInt32]
    let nonce: [UInt32]
    let counter: [UInt32]
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
    first: UInt32,
    count: UInt32,
    capacity: UInt32
) -> [UInt32] {
    return config.target
        + config.control
        + config.keyWords1To7
        + config.nonce
        + config.counter
        + [first, count, capacity]
}

private final class MetalSalsa2020Host {
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
        guard let filter = library.makeFunction(name: "salsa20_20_filter"),
              let blocks = library.makeFunction(name: "salsa20_20_blocks"),
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
            "salsa20_rounds": 20,
            "complete_block_words": 16,
        ]
    }

    private func threadsPerGroup(_ pipeline: MTLComputePipelineState) -> MTLSize {
        let limit = min(256, pipeline.maxTotalThreadsPerThreadgroup)
        let width = pipeline.threadExecutionWidth
        return MTLSize(width: max(width, (limit / width) * width), height: 1, depth: 1)
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
        guard UInt64(first) + UInt64(count) <= UInt64(UInt32.max) + 1 else {
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
        return [
            "op": "filter",
            "first": first,
            "count": count,
            "factual": (0..<Int(factualCount)).map { factualPointer[$0] }.sorted(),
            "control": (0..<Int(controlCount)).map { controlPointer[$0] }.sorted(),
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
        guard UInt64(first) + UInt64(count) <= UInt64(UInt32.max) + 1 else {
            throw HostError.invalidRequest("candidate interval wraps uint32")
        }
        let params = try makeBuffer(
            device: device,
            words: parameterWords(config: config, first: first, count: count, capacity: 1)
        )
        let output = try makeEmptyBuffer(device: device, wordCount: Int(count) * 16)
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
        let wordCount = Int(count) * 16
        let pointer = output.contents().bindMemory(to: UInt32.self, capacity: wordCount)
        return [
            "op": "blocks",
            "first": first,
            "count": count,
            "words": (0..<wordCount).map { pointer[$0] },
            "gpu_seconds": gpuSeconds,
        ]
    }
}

do {
    let host = try MetalSalsa2020Host()
    try emit([
        "op": "ready",
        "version": "salsa20-20-metal-native-v1",
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
                target: try word32Array(request["target"], field: "target", count: 16),
                control: try word32Array(
                    request["control"], field: "control", count: 16
                ),
                keyWords1To7: try word32Array(
                    request["key_words_1_to_7"], field: "key_words_1_to_7", count: 7
                ),
                nonce: try word32Array(request["nonce"], field: "nonce", count: 2),
                counter: try word32Array(request["counter"], field: "counter", count: 2)
            )
            configuration = config
            try emit([
                "op": "configured",
                "rounds": 20,
                "filter_words": 16,
                "full_block_comparison": true,
                "byte_semantics": "Bernstein_little_endian",
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
        let first = try uint32(request["first"], field: "first")
        let count = try uint32(request["count"], field: "count")
        if operation == "filter" {
            let capacity = try uint32(request["capacity"] ?? 64, field: "capacity")
            try emit(try host.filter(config: config, first: first, count: count, capacity: capacity))
        } else if operation == "blocks" {
            try emit(try host.blocks(config: config, first: first, count: count))
        } else {
            throw HostError.invalidRequest("unknown op \(operation)")
        }
    }
} catch {
    FileHandle.standardError.write(Data((String(describing: error) + "\n").utf8))
    exit(1)
}
