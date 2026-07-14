import Foundation
import CoreFoundation
import Metal

private let shaderSource = #"""
#include <metal_stdlib>
using namespace metal;

#define ASCON_MAX_MESSAGE_BYTES 32u
#define ASCON_MAX_AD_BYTES 32u
#define ASCON_TAG_BYTES 16u
#define ASCON_MAX_OUTPUT_BYTES 48u
#define ASCON_OUTPUT_WORDS 12u

struct SearchParams {
    uint message_words[8];
    uint associated_data_words[8];
    uint target_words[12];
    uint control_words[12];
    uint nonce_words[4];
    uint key_word1;
    uint key_word2;
    uint key_word3;
    uint message_length;
    uint associated_data_length;
    uint output_length;
    uint first_candidate;
    uint candidate_count;
    uint result_capacity;
};

inline ulong ror64(ulong value, uint shift) {
    return (value >> shift) | (value << (64u - shift));
}

inline void ascon_round(thread ulong *state, uchar constant_value) {
    ulong x0 = state[0];
    ulong x1 = state[1];
    ulong x2 = state[2] ^ ulong(constant_value);
    ulong x3 = state[3];
    ulong x4 = state[4];
    x0 ^= x4;
    x4 ^= x3;
    x2 ^= x1;
    ulong t0 = x0 ^ (~x1 & x2);
    ulong t1 = x1 ^ (~x2 & x3);
    ulong t2 = x2 ^ (~x3 & x4);
    ulong t3 = x3 ^ (~x4 & x0);
    ulong t4 = x4 ^ (~x0 & x1);
    t1 ^= t0;
    t0 ^= t4;
    t3 ^= t2;
    t2 = ~t2;
    state[0] = t0 ^ ror64(t0, 19u) ^ ror64(t0, 28u);
    state[1] = t1 ^ ror64(t1, 61u) ^ ror64(t1, 39u);
    state[2] = t2 ^ ror64(t2, 1u) ^ ror64(t2, 6u);
    state[3] = t3 ^ ror64(t3, 10u) ^ ror64(t3, 17u);
    state[4] = t4 ^ ror64(t4, 7u) ^ ror64(t4, 41u);
}

inline void ascon_p12(thread ulong *state) {
    ascon_round(state, 0xf0);
    ascon_round(state, 0xe1);
    ascon_round(state, 0xd2);
    ascon_round(state, 0xc3);
    ascon_round(state, 0xb4);
    ascon_round(state, 0xa5);
    ascon_round(state, 0x96);
    ascon_round(state, 0x87);
    ascon_round(state, 0x78);
    ascon_round(state, 0x69);
    ascon_round(state, 0x5a);
    ascon_round(state, 0x4b);
}

inline void ascon_p8(thread ulong *state) {
    ascon_round(state, 0xb4);
    ascon_round(state, 0xa5);
    ascon_round(state, 0x96);
    ascon_round(state, 0x87);
    ascon_round(state, 0x78);
    ascon_round(state, 0x69);
    ascon_round(state, 0x5a);
    ascon_round(state, 0x4b);
}

inline uchar packed_byte(constant uint *words, uint byte_offset) {
    return uchar((words[byte_offset >> 2u] >> (8u * (byte_offset & 3u))) & 0xffu);
}

inline ulong load_bytes(
    constant uint *words,
    uint byte_offset,
    uint byte_count
) {
    ulong value = 0ul;
    for (uint index = 0u; index < byte_count; ++index) {
        value |= ulong(packed_byte(words, byte_offset + index)) << (8u * index);
    }
    return value;
}

inline void store_bytes(
    thread uchar *output,
    uint byte_offset,
    ulong value,
    uint byte_count
) {
    for (uint index = 0u; index < byte_count; ++index) {
        output[byte_offset + index] = uchar(value >> (8u * index));
    }
}

inline uint pack_output_word(thread uchar *output, uint word_index) {
    const uint offset = word_index * 4u;
    return uint(output[offset])
        | (uint(output[offset + 1u]) << 8u)
        | (uint(output[offset + 2u]) << 16u)
        | (uint(output[offset + 3u]) << 24u);
}

inline void ascon_aead128_encrypt(
    constant SearchParams &params,
    uint candidate,
    thread uchar *output
) {
    for (uint index = 0u; index < ASCON_MAX_OUTPUT_BYTES; ++index) {
        output[index] = 0;
    }
    const ulong k0 = ulong(candidate) | (ulong(params.key_word1) << 32u);
    const ulong k1 = ulong(params.key_word2) | (ulong(params.key_word3) << 32u);
    const ulong n0 = ulong(params.nonce_words[0])
        | (ulong(params.nonce_words[1]) << 32u);
    const ulong n1 = ulong(params.nonce_words[2])
        | (ulong(params.nonce_words[3]) << 32u);
    thread ulong state[5] = {
        0x00001000808c0001ul,
        k0,
        k1,
        n0,
        n1,
    };
    ascon_p12(state);
    state[3] ^= k0;
    state[4] ^= k1;

    uint offset = 0u;
    uint remaining = params.associated_data_length;
    if (remaining != 0u) {
        while (remaining >= 16u) {
            state[0] ^= load_bytes(params.associated_data_words, offset, 8u);
            state[1] ^= load_bytes(params.associated_data_words, offset + 8u, 8u);
            ascon_p8(state);
            offset += 16u;
            remaining -= 16u;
        }
        if (remaining >= 8u) {
            state[0] ^= load_bytes(params.associated_data_words, offset, 8u);
            const uint tail = remaining - 8u;
            state[1] ^= load_bytes(params.associated_data_words, offset + 8u, tail);
            state[1] ^= 1ul << (8u * tail);
        } else {
            state[0] ^= load_bytes(params.associated_data_words, offset, remaining);
            state[0] ^= 1ul << (8u * remaining);
        }
        ascon_p8(state);
    }
    state[4] ^= 0x8000000000000000ul;

    offset = 0u;
    remaining = params.message_length;
    while (remaining >= 16u) {
        state[0] ^= load_bytes(params.message_words, offset, 8u);
        state[1] ^= load_bytes(params.message_words, offset + 8u, 8u);
        store_bytes(output, offset, state[0], 8u);
        store_bytes(output, offset + 8u, state[1], 8u);
        ascon_p8(state);
        offset += 16u;
        remaining -= 16u;
    }
    if (remaining >= 8u) {
        state[0] ^= load_bytes(params.message_words, offset, 8u);
        const uint tail = remaining - 8u;
        state[1] ^= load_bytes(params.message_words, offset + 8u, tail);
        store_bytes(output, offset, state[0], 8u);
        store_bytes(output, offset + 8u, state[1], tail);
        state[1] ^= 1ul << (8u * tail);
    } else {
        state[0] ^= load_bytes(params.message_words, offset, remaining);
        store_bytes(output, offset, state[0], remaining);
        state[0] ^= 1ul << (8u * remaining);
    }

    state[2] ^= k0;
    state[3] ^= k1;
    ascon_p12(state);
    state[3] ^= k0;
    state[4] ^= k1;
    store_bytes(output, params.message_length, state[3], 8u);
    store_bytes(output, params.message_length + 8u, state[4], 8u);
}

inline void record_candidate(
    device atomic_uint *count,
    device uint *candidates,
    uint capacity,
    uint candidate
) {
    const uint destination = atomic_fetch_add_explicit(
        count, 1u, memory_order_relaxed
    );
    if (destination < capacity) {
        candidates[destination] = candidate;
    }
}

kernel void ascon_aead128_filter(
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
    thread uchar output[ASCON_MAX_OUTPUT_BYTES];
    ascon_aead128_encrypt(params, candidate, output);
    bool factual_match = true;
    bool control_match = true;
    for (uint index = 0u; index < params.output_length; ++index) {
        factual_match = factual_match
            && output[index] == packed_byte(params.target_words, index);
        control_match = control_match
            && output[index] == packed_byte(params.control_words, index);
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

kernel void ascon_aead128_encryptions(
    constant SearchParams &params [[buffer(0)]],
    device uint *output_words [[buffer(1)]],
    uint gid [[thread_position_in_grid]]
) {
    if (gid >= params.candidate_count) {
        return;
    }
    const uint candidate = params.first_candidate + gid;
    thread uchar output[ASCON_MAX_OUTPUT_BYTES];
    ascon_aead128_encrypt(params, candidate, output);
    for (uint index = 0u; index < ASCON_OUTPUT_WORDS; ++index) {
        output_words[gid * ASCON_OUTPUT_WORDS + index] = pack_output_word(
            output, index
        );
    }
}
"""#

private let maxMessageBytes = 32
private let maxAssociatedDataBytes = 32
private let tagBytes = 16
private let outputWords = 12

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
    let messageWords: [UInt32]
    let associatedDataWords: [UInt32]
    let targetWords: [UInt32]
    let controlWords: [UInt32]
    let nonceWords: [UInt32]
    let keyWords1To3: [UInt32]
    let messageLength: UInt32
    let associatedDataLength: UInt32
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

private func wordArray(
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
    return config.messageWords
        + config.associatedDataWords
        + config.targetWords
        + config.controlWords
        + config.nonceWords
        + config.keyWords1To3
        + [
            config.messageLength,
            config.associatedDataLength,
            config.messageLength + UInt32(tagBytes),
            first,
            count,
            capacity,
        ]
}

private final class MetalAsconAEAD128Host {
    private let device: MTLDevice
    private let queue: MTLCommandQueue
    private let filterPipeline: MTLComputePipelineState
    private let encryptionsPipeline: MTLComputePipelineState

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
        guard let filter = library.makeFunction(name: "ascon_aead128_filter"),
              let encryptions = library.makeFunction(
                  name: "ascon_aead128_encryptions"
              ),
              let queue = device.makeCommandQueue() else {
            throw HostError.metal("pipeline function or command queue missing")
        }
        do {
            self.filterPipeline = try device.makeComputePipelineState(function: filter)
            self.encryptionsPipeline = try device.makeComputePipelineState(
                function: encryptions
            )
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
            "encryptions_execution_width": encryptionsPipeline.threadExecutionWidth,
            "encryptions_max_threads_per_group": (
                encryptionsPipeline.maxTotalThreadsPerThreadgroup
            ),
            "recommended_max_working_set_bytes": device.recommendedMaxWorkingSetSize,
            "shader_runtime_compiled": true,
            "sp800_232_little_endian_semantics": true,
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
                config: config,
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
            to: UInt32.self,
            capacity: Int(capacity)
        )
        let controlPointer = control.contents().bindMemory(
            to: UInt32.self,
            capacity: Int(capacity)
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

    func encryptions(
        config: Configuration,
        first: UInt32,
        count: UInt32
    ) throws -> [String: Any] {
        guard count > 0, count <= 4096 else {
            throw HostError.invalidRequest("encryption count must be in 1...4096")
        }
        guard UInt64(first) + UInt64(count) <= UInt64(UInt32.max) + 1 else {
            throw HostError.invalidRequest("candidate interval wraps uint32")
        }
        let params = try makeBuffer(
            device: device,
            words: parameterWords(config: config, first: first, count: count, capacity: 1)
        )
        let output = try makeEmptyBuffer(
            device: device,
            wordCount: Int(count) * outputWords
        )
        guard let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeComputeCommandEncoder() else {
            throw HostError.metal("encryptions command allocation failed")
        }
        encoder.setComputePipelineState(encryptionsPipeline)
        encoder.setBuffer(params, offset: 0, index: 0)
        encoder.setBuffer(output, offset: 0, index: 1)
        encoder.dispatchThreads(
            MTLSize(width: Int(count), height: 1, depth: 1),
            threadsPerThreadgroup: threadsPerGroup(encryptionsPipeline)
        )
        encoder.endEncoding()
        let gpuSeconds = try finish(commandBuffer)
        let wordCount = Int(count) * outputWords
        let pointer = output.contents().bindMemory(to: UInt32.self, capacity: wordCount)
        return [
            "op": "encryptions",
            "first": first,
            "count": count,
            "output_length": config.messageLength + UInt32(tagBytes),
            "words": (0..<wordCount).map { pointer[$0] },
            "gpu_seconds": gpuSeconds,
        ]
    }
}

do {
    let host = try MetalAsconAEAD128Host()
    try emit([
        "op": "ready",
        "version": "ascon-aead128-metal-native-v1",
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
                messageWords: try wordArray(
                    request["message_words"], field: "message_words", count: 8
                ),
                associatedDataWords: try wordArray(
                    request["associated_data_words"],
                    field: "associated_data_words",
                    count: 8
                ),
                targetWords: try wordArray(
                    request["target_words"], field: "target_words", count: 12
                ),
                controlWords: try wordArray(
                    request["control_words"], field: "control_words", count: 12
                ),
                nonceWords: try wordArray(
                    request["nonce_words"], field: "nonce_words", count: 4
                ),
                keyWords1To3: try wordArray(
                    request["key_words_1_to_3"],
                    field: "key_words_1_to_3",
                    count: 3
                ),
                messageLength: try uint32(
                    request["message_length"], field: "message_length"
                ),
                associatedDataLength: try uint32(
                    request["associated_data_length"],
                    field: "associated_data_length"
                )
            )
            guard config.messageLength <= UInt32(maxMessageBytes) else {
                throw HostError.invalidRequest("message_length exceeds 32 bytes")
            }
            guard config.associatedDataLength <= UInt32(maxAssociatedDataBytes) else {
                throw HostError.invalidRequest(
                    "associated_data_length exceeds 32 bytes"
                )
            }
            configuration = config
            try emit([
                "op": "configured",
                "message_length": config.messageLength,
                "associated_data_length": config.associatedDataLength,
                "output_length": config.messageLength + UInt32(tagBytes),
                "complete_ciphertext_and_tag_comparison": true,
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
            try emit(
                try host.filter(
                    config: config,
                    first: first,
                    count: count,
                    capacity: capacity
                )
            )
        } else if operation == "encryptions" {
            try emit(try host.encryptions(config: config, first: first, count: count))
        } else {
            throw HostError.invalidRequest("unknown op \(operation)")
        }
    }
} catch {
    FileHandle.standardError.write(Data((String(describing: error) + "\n").utf8))
    exit(1)
}
