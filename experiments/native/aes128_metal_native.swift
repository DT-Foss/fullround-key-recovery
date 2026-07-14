import Foundation
import CoreFoundation
import Metal

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

struct SearchParams {
    uint plaintext[32];
    uint target[32];
    uint control[32];
    uint key_word0;
    uint key_word1;
    uint key_word2;
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

constant uchar AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

constant uchar AES_RCON[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
};

inline uchar word_byte(uint word, uint row) {
    return uchar((word >> (24u - 8u * row)) & 0xffu);
}

inline uint aes_sub_rot_word(uint word, uint round_index) {
    return ((uint(AES_SBOX[(word >> 16u) & 0xffu])
            ^ uint(AES_RCON[round_index])) << 24u)
        | (uint(AES_SBOX[(word >> 8u) & 0xffu]) << 16u)
        | (uint(AES_SBOX[word & 0xffu]) << 8u)
        | uint(AES_SBOX[(word >> 24u) & 0xffu]);
}

inline uchar aes_xtime(uchar value) {
    const uint raw = uint(value);
    return uchar(((raw << 1u) ^ ((raw & 0x80u) ? 0x1bu : 0u)) & 0xffu);
}

inline void aes_add_round_key(thread uchar *state, thread const uint *round_key) {
    for (uint column = 0u; column < 4u; ++column) {
        for (uint row = 0u; row < 4u; ++row) {
            state[4u * column + row] ^= word_byte(round_key[column], row);
        }
    }
}

inline void aes_sub_bytes(thread uchar *state) {
    for (uint index = 0u; index < 16u; ++index) {
        state[index] = AES_SBOX[state[index]];
    }
}

inline void aes_shift_rows(thread uchar *state) {
    thread uchar shifted[16];
    for (uint column = 0u; column < 4u; ++column) {
        for (uint row = 0u; row < 4u; ++row) {
            shifted[4u * column + row] = state[4u * ((column + row) & 3u) + row];
        }
    }
    for (uint index = 0u; index < 16u; ++index) {
        state[index] = shifted[index];
    }
}

inline void aes_mix_columns(thread uchar *state) {
    for (uint column = 0u; column < 4u; ++column) {
        const uint offset = 4u * column;
        const uchar a0 = state[offset];
        const uchar a1 = state[offset + 1u];
        const uchar a2 = state[offset + 2u];
        const uchar a3 = state[offset + 3u];
        const uchar total = a0 ^ a1 ^ a2 ^ a3;
        state[offset] = a0 ^ total ^ aes_xtime(a0 ^ a1);
        state[offset + 1u] = a1 ^ total ^ aes_xtime(a1 ^ a2);
        state[offset + 2u] = a2 ^ total ^ aes_xtime(a2 ^ a3);
        state[offset + 3u] = a3 ^ total ^ aes_xtime(a3 ^ a0);
    }
}

inline void aes128_encrypt(
    thread uchar *state,
    uint key_word0,
    uint key_word1,
    uint key_word2,
    uint candidate
) {
    thread uint round_key[4] = {key_word0, key_word1, key_word2, candidate};
    aes_add_round_key(state, round_key);
    for (uint round = 1u; round <= 10u; ++round) {
        const uint schedule = aes_sub_rot_word(round_key[3], round - 1u);
        round_key[0] ^= schedule;
        round_key[1] ^= round_key[0];
        round_key[2] ^= round_key[1];
        round_key[3] ^= round_key[2];
        aes_sub_bytes(state);
        aes_shift_rows(state);
        if (round < 10u) {
            aes_mix_columns(state);
        }
        aes_add_round_key(state, round_key);
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

kernel void aes128_filter(
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
    bool factual_match = true;
    bool control_match = true;
    for (uint block = 0u; block < 2u; ++block) {
        if (!factual_match && !control_match) {
            break;
        }
        thread uchar state[16];
        const uint block_offset = block * 16u;
        for (uint index = 0u; index < 16u; ++index) {
            state[index] = uchar(params.plaintext[block_offset + index]);
        }
        aes128_encrypt(
            state,
            params.key_word0,
            params.key_word1,
            params.key_word2,
            candidate
        );
        for (uint index = 0u; index < 16u; ++index) {
            const uint output = uint(state[index]);
            factual_match = factual_match
                && output == params.target[block_offset + index];
            control_match = control_match
                && output == params.control[block_offset + index];
        }
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

kernel void aes128_blocks(
    constant SearchParams &params [[buffer(0)]],
    device uint *output [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    const uint candidate = params.first_candidate + gid;
    for (uint block = 0u; block < 2u; ++block) {
        thread uchar state[16];
        const uint block_offset = block * 16u;
        for (uint index = 0u; index < 16u; ++index) {
            state[index] = uchar(params.plaintext[block_offset + index]);
        }
        aes128_encrypt(
            state,
            params.key_word0,
            params.key_word1,
            params.key_word2,
            candidate
        );
        for (uint index = 0u; index < 16u; ++index) {
            output[gid * 32u + block_offset + index] = uint(state[index]);
        }
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
    let keyWords0To2: [UInt32]
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

private func wordArray(_ value: Any?, field: String, count: Int) throws -> [UInt32] {
    guard let values = value as? [Any], values.count == count else {
        throw HostError.invalidRequest("\(field) must contain \(count) words")
    }
    return try values.enumerated().map {
        try uint32($0.element, field: "\(field)[\($0.offset)]")
    }
}

private func byteArray(_ value: Any?, field: String, count: Int) throws -> [UInt32] {
    let values = try wordArray(value, field: field, count: count)
    guard values.allSatisfy({ $0 <= 0xFF }) else {
        throw HostError.invalidRequest("\(field) values must be exact bytes")
    }
    return values
}

private func makeBuffer(device: MTLDevice, words: [UInt32]) throws -> MTLBuffer {
    let buffer = words.withUnsafeBytes { raw in
        device.makeBuffer(
            bytes: raw.baseAddress!,
            length: raw.count,
            options: .storageModeShared
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
        + config.keyWords0To2
        + [first, count, capacity]
}

private final class MetalAES128Host {
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
        guard let filter = library.makeFunction(name: "aes128_filter"),
              let blocks = library.makeFunction(name: "aes128_blocks"),
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
            "shader_runtime_compiled": true,
            "fips197_external_byte_order": true,
            "candidate_maps_to_key_bytes_12_through_15_big_endian": true,
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
                commandBuffer.error?.localizedDescription ?? "command buffer did not complete"
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
            words: parameterWords(config: config, first: first, count: count, capacity: capacity)
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
        let factualPointer = factual.contents().bindMemory(to: UInt32.self, capacity: Int(capacity))
        let controlPointer = control.contents().bindMemory(to: UInt32.self, capacity: Int(capacity))
        return [
            "op": "filter",
            "first": first,
            "count": count,
            "factual": (0..<Int(factualCount)).map { factualPointer[$0] }.sorted(),
            "control": (0..<Int(controlCount)).map { controlPointer[$0] }.sorted(),
            "gpu_seconds": gpuSeconds,
        ]
    }

    func blocks(config: Configuration, first: UInt32, count: UInt32) throws -> [String: Any] {
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
        let output = try makeEmptyBuffer(device: device, wordCount: Int(count) * 32)
        guard let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder() else {
            throw HostError.metal("blocks command allocation failed")
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
        return [
            "op": "blocks",
            "first": first,
            "count": count,
            "bytes": (0..<wordCount).map { pointer[$0] },
            "gpu_seconds": gpuSeconds,
        ]
    }
}

do {
    let host = try MetalAES128Host()
    try emit([
        "op": "ready",
        "version": "aes128-fips197-metal-native-v1",
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
                plaintext: try byteArray(request["plaintext"], field: "plaintext", count: 32),
                target: try byteArray(request["target"], field: "target", count: 32),
                control: try byteArray(request["control"], field: "control", count: 32),
                keyWords0To2: try wordArray(
                    request["key_words_0_to_2"], field: "key_words_0_to_2", count: 3
                )
            )
            configuration = config
            try emit([
                "op": "configured",
                "plaintext_blocks": 2,
                "filter_bits": 256,
                "candidate_key_word": 3,
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
