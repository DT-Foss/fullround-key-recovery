import Foundation
import Metal

private let hostVersion = "chacha20-metal-w43-grouped-v1"
private let word1LowMask: UInt32 = 0x7FF

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

struct GroupSearchParams {
    uint initial[16];
    uint target[2];
    uint control[2];
    uint first_word0;
    uint word0_count;
    uint outer_first;
    uint outer_count;
    uint result_capacity;
};

inline uint rotl32(uint value, uint shift) {
    return (value << shift) | (value >> (32u - shift));
}

inline void quarter_round(thread uint *state, uint a, uint b, uint c, uint d) {
    state[a] += state[b];
    state[d] = rotl32(state[d] ^ state[a], 16u);
    state[c] += state[d];
    state[b] = rotl32(state[b] ^ state[c], 12u);
    state[a] += state[b];
    state[d] = rotl32(state[d] ^ state[a], 8u);
    state[c] += state[d];
    state[b] = rotl32(state[b] ^ state[c], 7u);
}

inline void chacha20_block(
    thread uint *state,
    constant GroupSearchParams &params,
    uint word0,
    uint outer
) {
    thread uint initial[16];
    for (uint word = 0u; word < 16u; ++word) {
        initial[word] = params.initial[word];
    }
    initial[4] = word0;
    initial[5] = (initial[5] & 0xFFFFF800u) | outer;
    for (uint word = 0u; word < 16u; ++word) {
        state[word] = initial[word];
    }
    for (uint double_round = 0u; double_round < 10u; ++double_round) {
        quarter_round(state, 0u, 4u, 8u, 12u);
        quarter_round(state, 1u, 5u, 9u, 13u);
        quarter_round(state, 2u, 6u, 10u, 14u);
        quarter_round(state, 3u, 7u, 11u, 15u);
        quarter_round(state, 0u, 5u, 10u, 15u);
        quarter_round(state, 1u, 6u, 11u, 12u);
        quarter_round(state, 2u, 7u, 8u, 13u);
        quarter_round(state, 3u, 4u, 9u, 14u);
    }
    for (uint word = 0u; word < 16u; ++word) {
        state[word] += initial[word];
    }
}

kernel void chacha20_group_filter(
    constant GroupSearchParams &params [[buffer(0)]],
    device atomic_uint *counts [[buffer(1)]],
    device uint2 *factual_candidates [[buffer(2)]],
    device uint2 *control_candidates [[buffer(3)]],
    uint2 gid [[thread_position_in_grid]]
) {
    if (gid.x >= params.word0_count || gid.y >= params.outer_count) {
        return;
    }
    const uint word0 = params.first_word0 + gid.x;
    const uint outer = params.outer_first + gid.y;
    thread uint state[16];
    chacha20_block(state, params, word0, outer);
    if (state[0] == params.target[0] && state[1] == params.target[1]) {
        const uint offset = atomic_fetch_add_explicit(
            &counts[0], 1u, memory_order_relaxed
        );
        if (offset < params.result_capacity) {
            factual_candidates[offset] = uint2(word0, outer);
        }
    }
    if (state[0] == params.control[0] && state[1] == params.control[1]) {
        const uint offset = atomic_fetch_add_explicit(
            &counts[1], 1u, memory_order_relaxed
        );
        if (offset < params.result_capacity) {
            control_candidates[offset] = uint2(word0, outer);
        }
    }
}

kernel void chacha20_group_blocks(
    constant GroupSearchParams &params [[buffer(0)]],
    device uint *output [[buffer(1)]],
    uint2 gid [[thread_position_in_grid]]
) {
    if (gid.x >= params.word0_count || gid.y >= params.outer_count) {
        return;
    }
    const uint word0 = params.first_word0 + gid.x;
    const uint outer = params.outer_first + gid.y;
    thread uint state[16];
    chacha20_block(state, params, word0, outer);
    const uint linear = gid.y * params.word0_count + gid.x;
    for (uint word = 0u; word < 16u; ++word) {
        output[linear * 16u + word] = state[word];
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
    let initial: [UInt32]
    let target: [UInt32]
    let control: [UInt32]
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

private func makeEmptyBuffer(
    device: MTLDevice,
    wordCount: Int
) throws -> MTLBuffer {
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
    firstWord0: UInt32,
    word0Count: UInt32,
    outerFirst: UInt32,
    outerCount: UInt32,
    capacity: UInt32
) -> [UInt32] {
    return config.initial + config.target + config.control + [
        firstWord0, word0Count, outerFirst, outerCount, capacity,
    ]
}

private final class MetalChaCha20GroupedHost {
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
        guard let filter = library.makeFunction(name: "chacha20_group_filter"),
              let blocks = library.makeFunction(name: "chacha20_group_blocks"),
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
            "two_dimensional_candidate_grid": true,
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
                commandBuffer.error?.localizedDescription ?? "command buffer did not complete"
            )
        }
        return max(0, commandBuffer.gpuEndTime - commandBuffer.gpuStartTime)
    }

    private func validateGrid(
        firstWord0: UInt32,
        word0Count: UInt32,
        outerFirst: UInt32,
        outerCount: UInt32
    ) throws {
        guard word0Count > 0, outerCount > 0 else {
            throw HostError.invalidRequest("grid dimensions must be positive")
        }
        guard UInt64(firstWord0) + UInt64(word0Count) <= UInt64(UInt32.max) + 1 else {
            throw HostError.invalidRequest("word0 interval wraps uint32")
        }
        guard UInt64(outerFirst) + UInt64(outerCount) <= 2048 else {
            throw HostError.invalidRequest("outer interval exceeds the 11-bit domain")
        }
        guard UInt64(word0Count) * UInt64(outerCount) <= UInt64(UInt32.max) else {
            throw HostError.invalidRequest("candidate grid exceeds uint32 indexing")
        }
    }

    func filterGroup(
        config: Configuration,
        firstWord0: UInt32,
        word0Count: UInt32,
        outerFirst: UInt32,
        outerCount: UInt32,
        capacity: UInt32
    ) throws -> [String: Any] {
        try validateGrid(
            firstWord0: firstWord0,
            word0Count: word0Count,
            outerFirst: outerFirst,
            outerCount: outerCount
        )
        guard capacity > 0 else {
            throw HostError.invalidRequest("capacity must be positive")
        }
        let params = try makeBuffer(
            device: device,
            words: parameterWords(
                config: config,
                firstWord0: firstWord0,
                word0Count: word0Count,
                outerFirst: outerFirst,
                outerCount: outerCount,
                capacity: capacity
            )
        )
        let counts = try makeEmptyBuffer(device: device, wordCount: 2)
        let factual = try makeEmptyBuffer(device: device, wordCount: Int(capacity) * 2)
        let control = try makeEmptyBuffer(device: device, wordCount: Int(capacity) * 2)
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
            MTLSize(width: Int(word0Count), height: Int(outerCount), depth: 1),
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
        func pairs(_ buffer: MTLBuffer, _ count: UInt32) -> [[UInt32]] {
            let pointer = buffer.contents().bindMemory(
                to: UInt32.self,
                capacity: Int(capacity) * 2
            )
            return (0..<Int(count)).map { [pointer[$0 * 2], pointer[$0 * 2 + 1]] }
                .sorted { lhs, rhs in
                    if lhs[1] == rhs[1] { return lhs[0] < rhs[0] }
                    return lhs[1] < rhs[1]
                }
        }
        return [
            "op": "filter_group",
            "first_word0": firstWord0,
            "word0_count": word0Count,
            "outer_first": outerFirst,
            "outer_count": outerCount,
            "logical_candidates": UInt64(word0Count) * UInt64(outerCount),
            "factual": pairs(factual, factualCount),
            "control": pairs(control, controlCount),
            "gpu_seconds": gpuSeconds,
        ]
    }

    func blocksGroup(
        config: Configuration,
        firstWord0: UInt32,
        word0Count: UInt32,
        outerFirst: UInt32,
        outerCount: UInt32
    ) throws -> [String: Any] {
        try validateGrid(
            firstWord0: firstWord0,
            word0Count: word0Count,
            outerFirst: outerFirst,
            outerCount: outerCount
        )
        let candidates = UInt64(word0Count) * UInt64(outerCount)
        guard candidates <= 4096 else {
            throw HostError.invalidRequest("blocks_group is limited to 4096 candidates")
        }
        let params = try makeBuffer(
            device: device,
            words: parameterWords(
                config: config,
                firstWord0: firstWord0,
                word0Count: word0Count,
                outerFirst: outerFirst,
                outerCount: outerCount,
                capacity: 1
            )
        )
        let output = try makeEmptyBuffer(device: device, wordCount: Int(candidates) * 16)
        guard let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder() else {
            throw HostError.metal("blocks command allocation failed")
        }
        encoder.setComputePipelineState(blocksPipeline)
        encoder.setBuffer(params, offset: 0, index: 0)
        encoder.setBuffer(output, offset: 0, index: 1)
        encoder.dispatchThreads(
            MTLSize(width: Int(word0Count), height: Int(outerCount), depth: 1),
            threadsPerThreadgroup: threadsPerGroup(blocksPipeline)
        )
        encoder.endEncoding()
        let gpuSeconds = try finish(commandBuffer)
        let wordCount = Int(candidates) * 16
        let pointer = output.contents().bindMemory(to: UInt32.self, capacity: wordCount)
        let words = (0..<wordCount).map { pointer[$0] }
        return [
            "op": "blocks_group",
            "first_word0": firstWord0,
            "word0_count": word0Count,
            "outer_first": outerFirst,
            "outer_count": outerCount,
            "words": words,
            "gpu_seconds": gpuSeconds,
        ]
    }
}

do {
    let host = try MetalChaCha20GroupedHost()
    try emit(["op": "ready", "version": hostVersion, "metal": host.identity])
    var configuration: Configuration?
    while let line = readLine() {
        let request = try parseObject(line)
        guard let operation = request["op"] as? String else {
            throw HostError.invalidRequest("op is required")
        }
        if operation == "configure" {
            let initial = try uint32Array(request["initial"], field: "initial", count: 16)
            guard initial[5] & word1LowMask == 0 else {
                throw HostError.invalidRequest("initial word1 low 11 bits must be zero")
            }
            configuration = Configuration(
                initial: initial,
                target: try uint32Array(request["target"], field: "target", count: 2),
                control: try uint32Array(request["control"], field: "control", count: 2)
            )
            try emit(["op": "configured", "initial_words": 16, "filter_words": 2])
            continue
        }
        if operation == "quit" {
            try emit(["op": "quit"])
            break
        }
        guard let config = configuration else {
            throw HostError.invalidRequest("configure must precede execution")
        }
        let firstWord0 = try uint32(request["first_word0"], field: "first_word0")
        let word0Count = try uint32(request["word0_count"], field: "word0_count")
        let outerFirst = try uint32(request["outer_first"], field: "outer_first")
        let outerCount = try uint32(request["outer_count"], field: "outer_count")
        if operation == "filter_group" {
            let capacity = try uint32(request["capacity"] ?? 64, field: "capacity")
            try emit(
                try host.filterGroup(
                    config: config,
                    firstWord0: firstWord0,
                    word0Count: word0Count,
                    outerFirst: outerFirst,
                    outerCount: outerCount,
                    capacity: capacity
                )
            )
        } else if operation == "blocks_group" {
            try emit(
                try host.blocksGroup(
                    config: config,
                    firstWord0: firstWord0,
                    word0Count: word0Count,
                    outerFirst: outerFirst,
                    outerCount: outerCount
                )
            )
        } else {
            throw HostError.invalidRequest("unknown op \(operation)")
        }
    }
} catch {
    let message = String(describing: error)
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}
