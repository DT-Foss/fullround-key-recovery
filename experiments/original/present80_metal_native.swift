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
    uint key_middle32;
    uint key_high16;
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

constant uchar PRESENT_SBOX[16] = {
    0xcu, 0x5u, 0x6u, 0xbu, 0x9u, 0x0u, 0xau, 0xdu,
    0x3u, 0xeu, 0xfu, 0x8u, 0x4u, 0x7u, 0x1u, 0x2u,
};

constant uchar PRESENT_PBOX[64] = {
     0u, 16u, 32u, 48u,  1u, 17u, 33u, 49u,
     2u, 18u, 34u, 50u,  3u, 19u, 35u, 51u,
     4u, 20u, 36u, 52u,  5u, 21u, 37u, 53u,
     6u, 22u, 38u, 54u,  7u, 23u, 39u, 55u,
     8u, 24u, 40u, 56u,  9u, 25u, 41u, 57u,
    10u, 26u, 42u, 58u, 11u, 27u, 43u, 59u,
    12u, 28u, 44u, 60u, 13u, 29u, 45u, 61u,
    14u, 30u, 46u, 62u, 15u, 31u, 47u, 63u,
};

inline ulong present_sbox_layer(ulong state) {
    ulong output = 0ul;
    for (uint nibble = 0u; nibble < 16u; ++nibble) {
        const uint value = uint((state >> (4u * nibble)) & 0xful);
        output |= ulong(PRESENT_SBOX[value]) << (4u * nibble);
    }
    return output;
}

inline ulong present_permutation_layer(ulong state) {
    ulong output = 0ul;
    for (uint source = 0u; source < 64u; ++source) {
        output |= ((state >> source) & 1ul) << uint(PRESENT_PBOX[source]);
    }
    return output;
}

inline ulong2 present80_update_key(
    ulong high64,
    uint low16,
    uint round_index
) {
    // The 80-bit register is `(high64 << 16) | low16`.  Rotate left by
    // 61 (equivalently right by 19) without introducing a 128-bit type.
    const ulong low19 = ((high64 & 0x7ul) << 16u) | ulong(low16 & 0xffffu);
    ulong next_high64 = (high64 >> 19u) | (low19 << 45u);
    uint next_low16 = uint((high64 >> 3u) & 0xfffful);
    const uint top_nibble = uint(next_high64 >> 60u);
    next_high64 = (next_high64 & 0x0ffffffffffffffful)
        | (ulong(PRESENT_SBOX[top_nibble]) << 60u);
    next_low16 ^= (round_index & 1u) << 15u;
    next_high64 ^= ulong(round_index >> 1u);
    return ulong2(next_high64, ulong(next_low16));
}

inline ulong2 present80_encrypt_two(
    ulong2 states,
    uint candidate,
    constant SearchParams &params
) {
    ulong key_high64 = (ulong(params.key_high16) << 48u)
        | (ulong(params.key_middle32) << 16u)
        | ulong(candidate >> 16u);
    uint key_low16 = candidate & 0xffffu;
    for (uint round_index = 1u; round_index <= 31u; ++round_index) {
        states.x = present_permutation_layer(
            present_sbox_layer(states.x ^ key_high64)
        );
        states.y = present_permutation_layer(
            present_sbox_layer(states.y ^ key_high64)
        );
        const ulong2 next_key = present80_update_key(
            key_high64, key_low16, round_index
        );
        key_high64 = next_key.x;
        key_low16 = uint(next_key.y);
    }
    // K32 is a whitening key only: no S-box or permutation follows it.
    states.x ^= key_high64;
    states.y ^= key_high64;
    return states;
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

kernel void present80_filter(
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
    const ulong2 output = present80_encrypt_two(
        ulong2(
            (ulong(params.plaintext[0]) << 32u) | ulong(params.plaintext[1]),
            (ulong(params.plaintext[2]) << 32u) | ulong(params.plaintext[3])
        ),
        candidate,
        params
    );
    const uint words[4] = {
        uint(output.x >> 32u),
        uint(output.x),
        uint(output.y >> 32u),
        uint(output.y),
    };
    bool factual_match = true;
    bool control_match = true;
    for (uint offset = 0u; offset < 4u; ++offset) {
        factual_match = factual_match
            && words[offset] == params.target[offset];
        control_match = control_match
            && words[offset] == params.control[offset];
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

kernel void present80_blocks(
    constant SearchParams &params [[buffer(0)]],
    device uint *output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    const uint candidate = params.first_candidate + gid;
    const ulong2 ciphertext = present80_encrypt_two(
        ulong2(
            (ulong(params.plaintext[0]) << 32u) | ulong(params.plaintext[1]),
            (ulong(params.plaintext[2]) << 32u) | ulong(params.plaintext[3])
        ),
        candidate,
        params
    );
    output[gid * 4u] = uint(ciphertext.x >> 32u);
    output[gid * 4u + 1u] = uint(ciphertext.x);
    output[gid * 4u + 2u] = uint(ciphertext.y >> 32u);
    output[gid * 4u + 3u] = uint(ciphertext.y);
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
    let keyMiddle32: UInt32
    let keyHigh16: UInt32
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
        + [config.keyMiddle32, config.keyHigh16, first, count, capacity]
}

private final class MetalPresent80Host {
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
        guard let filter = library.makeFunction(name: "present80_filter"),
              let blocks = library.makeFunction(name: "present80_blocks"),
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
    let host = try MetalPresent80Host()
    try emit([
        "op": "ready",
        "version": "present80-metal-native-v1",
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
                keyMiddle32: try uint32(
                    request["key_middle32"], field: "key_middle32"
                ),
                keyHigh16: try uint32(
                    request["key_high16"], field: "key_high16"
                )
            )
            guard config.keyHigh16 <= UInt32(UInt16.max) else {
                throw HostError.invalidRequest("key_high16 must fit in uint16")
            }
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
