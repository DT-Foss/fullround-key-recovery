import Foundation
import Metal

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

struct SearchParams {
    uint plaintext[6];
    uint target[6];
    uint control[6];
    uint key2;
    uint key3;
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

inline uint rol16(uint value, uint shift) {
    value &= 0xffffu;
    return ((value << shift) | (value >> (16u - shift))) & 0xffffu;
}

inline uint ror16(uint value, uint shift) {
    value &= 0xffffu;
    return ((value >> shift) | (value << (16u - shift))) & 0xffffu;
}

inline void speck32_64_round_keys(
    thread uint *round_keys,
    uint candidate,
    constant SearchParams &params
) {
    thread uint l_words[24];
    round_keys[0] = candidate & 0xffffu;
    l_words[0] = (candidate >> 16u) & 0xffffu;
    l_words[1] = params.key2 & 0xffffu;
    l_words[2] = params.key3 & 0xffffu;
    for (uint round = 0u; round < 21u; ++round) {
        const uint next_l = (
            (ror16(l_words[round], 7u) + round_keys[round]) ^ round
        ) & 0xffffu;
        l_words[round + 3u] = next_l;
        round_keys[round + 1u] = (rol16(round_keys[round], 2u) ^ next_l) & 0xffffu;
    }
}

inline uint2 speck32_64_encrypt(uint2 state, thread const uint *round_keys) {
    uint x = state.x & 0xffffu;
    uint y = state.y & 0xffffu;
    for (uint round = 0u; round < 22u; ++round) {
        x = ((ror16(x, 7u) + y) ^ round_keys[round]) & 0xffffu;
        y = (rol16(y, 2u) ^ x) & 0xffffu;
    }
    return uint2(x, y);
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

kernel void speck32_64_filter(
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
    thread uint round_keys[22];
    speck32_64_round_keys(round_keys, candidate, params);
    bool factual_match = true;
    bool control_match = true;
    for (uint block = 0u; block < 3u; ++block) {
        if (!factual_match && !control_match) {
            break;
        }
        const uint offset = block * 2u;
        const uint2 output = speck32_64_encrypt(
            uint2(params.plaintext[offset], params.plaintext[offset + 1u]),
            round_keys
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

kernel void speck32_64_blocks(
    constant SearchParams &params [[buffer(0)]],
    device uint *output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    const uint candidate = params.first_candidate + gid;
    thread uint round_keys[22];
    speck32_64_round_keys(round_keys, candidate, params);
    for (uint block = 0u; block < 3u; ++block) {
        const uint offset = block * 2u;
        const uint2 ciphertext = speck32_64_encrypt(
            uint2(params.plaintext[offset], params.plaintext[offset + 1u]),
            round_keys
        );
        output[gid * 6u + offset] = ciphertext.x;
        output[gid * 6u + offset + 1u] = ciphertext.y;
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
    let raw = number.uint64Value
    guard raw <= UInt64(UInt32.max), number.doubleValue >= 0 else {
        throw HostError.invalidRequest("\(field) exceeds uint32")
    }
    return UInt32(raw)
}

private func word16(_ value: Any?, field: String) throws -> UInt32 {
    let word = try uint32(value, field: field)
    guard word <= 0xffff else {
        throw HostError.invalidRequest("\(field) exceeds uint16")
    }
    return word
}

private func word16Array(
    _ value: Any?,
    field: String,
    count: Int
) throws -> [UInt32] {
    guard let values = value as? [Any], values.count == count else {
        throw HostError.invalidRequest("\(field) must contain \(count) words")
    }
    return try values.enumerated().map {
        try word16($0.element, field: "\(field)[\($0.offset)]")
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
        + [config.key2, config.key3, first, count, capacity]
}

private final class MetalSpeck3264Host {
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
        guard let filter = library.makeFunction(name: "speck32_64_filter"),
              let blocks = library.makeFunction(name: "speck32_64_blocks"),
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
        let output = try makeEmptyBuffer(device: device, wordCount: Int(count) * 6)
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
        let wordCount = Int(count) * 6
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
    let host = try MetalSpeck3264Host()
    try emit([
        "op": "ready",
        "version": "speck32-64-metal-native-v1",
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
                plaintext: try word16Array(
                    request["plaintext"], field: "plaintext", count: 6
                ),
                target: try word16Array(request["target"], field: "target", count: 6),
                control: try word16Array(
                    request["control"], field: "control", count: 6
                ),
                key2: try word16(request["key2"], field: "key2"),
                key3: try word16(request["key3"], field: "key3")
            )
            configuration = config
            try emit(["op": "configured", "plaintext_blocks": 3, "filter_words": 6])
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
