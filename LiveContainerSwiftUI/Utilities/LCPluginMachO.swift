// SPDX-License-Identifier: GPL-3.0-only
// Load-command editing follows the approach used by Feather's MIT-licensed
// Zsign dependency. Rewritten in Swift with bounded reads and no segment relocation.
import Foundation

struct LCPluginError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct LCPluginMachO {
    struct Slice { let offset: Int; let size: Int }
    struct Command { let type: UInt32; var bytes: Data }
    private var data: Data
    private let slices: [Slice]
    private let commandAlignment: Int
    private static let loads: Set<UInt32> = [0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20]

    public init(url: URL) throws {
        do { try self.init(data: Data(contentsOf: url)) }
        catch { throw LCPluginError("\(url.lastPathComponent)：\(error.localizedDescription)") }
    }
    public init(data: Data) throws {
        try self.init(data: data, commandAlignment: 8)
    }

    // Some injection tools leave 4-byte alignment. Only read dependencies this way; editing stays strict.
    static func inspectDependencies(at url: URL) throws -> (dependencies: [String], runtimeSearchPaths: Set<String>) {
        let macho = try LCPluginMachO(data: Data(contentsOf: url), commandAlignment: 4)
        return (try macho.dependencies, try macho.runtimeSearchPaths)
    }

    private init(data: Data, commandAlignment: Int) throws {
        self.data = data
        self.commandAlignment = commandAlignment
        let magic = try data.word(0)
        if magic == 0xfeedfacf {
            slices = [Slice(offset: 0, size: data.count)]
        } else if magic == 0xbebafeca || magic == 0xbfbafeca || magic == 0xcafebabe || magic == 0xcafebabf {
            let big = magic == 0xbebafeca || magic == 0xbfbafeca
            let wide = magic == 0xbfbafeca || magic == 0xcafebabf
            let count = Int(try data.word(4, big: big))
            let stride = wide ? 32 : 20
            guard count > 0, count <= 64, 8 + count * stride <= data.count else { throw LCPluginError("Fat Mach-O 架构表损坏。") }
            var found: [Slice] = []
            for i in 0..<count {
                let p = 8 + i * stride
                let offset = wide ? try data.long(p + 8, big: big) : UInt64(try data.word(p + 8, big: big))
                let size = wide ? try data.long(p + 16, big: big) : UInt64(try data.word(p + 12, big: big))
                guard size >= 32, offset >= UInt64(8 + count * stride), offset <= UInt64(data.count), size <= UInt64(data.count) - offset else {
                    throw LCPluginError("Fat Mach-O 切片范围损坏。")
                }
                let slice = Slice(offset: Int(offset), size: Int(size))
                guard !found.contains(where: { $0.offset < slice.offset + slice.size && slice.offset < $0.offset + $0.size }) else {
                    throw LCPluginError("Mach-O 架构切片重叠。")
                }
                guard try data.word(slice.offset) == 0xfeedfacf else {
                    throw LCPluginError("此文件含不支持的 32 位或大端 Mach-O 切片，请使用 64 位 iOS 包。")
                }
                found.append(slice)
            }
            slices = found
        } else { throw LCPluginError("文件不是有效的 64 位 Mach-O。") }
        for slice in slices { _ = try commands(slice) }
    }

    func requireARM64() throws {
        guard try slices.contains(where: { try data.word($0.offset + 4) == 0x0100000c }) else {
            throw LCPluginError("插件不包含 iOS arm64 架构。")
        }
    }

    public var dependencies: [String] {
        get throws {
            var result: Set<String> = []
            for slice in slices {
                for cmd in try commands(slice) where Self.loads.contains(cmd.type) {
                    result.insert(try path(cmd))
                }
            }
            return result.sorted()
        }
    }

    public func requireDecrypted() throws {
        for slice in slices {
            for cmd in try commands(slice) where cmd.type == 0x21 || cmd.type == 0x2c {
                if try cmd.bytes.word(16) != 0 { throw LCPluginError("IPA 主程序仍被加密。请使用已解密、能在 LiveContainer 中运行的 IPA。") }
            }
        }
    }

    public var runtimeSearchPaths: Set<String> {
        get throws {
            var paths: Set<String> = []
            for slice in slices {
                for command in try commands(slice) where command.type == 0x8000001c {
                    let offset = Int(try command.bytes.word(8))
                    guard offset >= 12, offset < command.bytes.count,
                          let end = command.bytes[offset...].firstIndex(of: 0),
                          let value = String(data: command.bytes[offset..<end], encoding: .utf8) else {
                        throw LCPluginError("Mach-O 的 rpath 格式损坏。")
                    }
                    paths.insert(value)
                }
            }
            return paths
        }
    }

    public mutating func edit(add: [String] = [], remove: Set<String> = [], replacements: [String: String] = [:], installID: String? = nil) throws {
        var output = data
        for slice in slices {
            let old = try commands(slice)
            var revised: [Command] = []
            for var cmd in old {
                if Self.loads.contains(cmd.type) || cmd.type == 0xd {
                    let original = try path(cmd)
                    if Self.loads.contains(cmd.type), remove.contains(original) { continue }
                    if let replacement = cmd.type == 0xd ? installID : replacements[original] {
                        cmd = try replacingPath(cmd, with: replacement)
                    }
                }
                revised.append(cmd)
            }
            var existing = Set(try revised.filter { Self.loads.contains($0.type) }.map { try path($0) })
            for name in add where !existing.contains(name) {
                var bytes = Data(repeating: 0, count: 24)
                bytes.put(0xc, at: 0); bytes.put(24, at: 8)
                revised.append(try replacingPath(Command(type: 0xc, bytes: bytes), with: name))
                existing.insert(name)
            }
            let bytes = revised.reduce(into: Data()) { $0.append($1.bytes) }
            let oldSize = Int(try data.word(slice.offset + 20))
            let available = try capacity(slice, commands: old)
            guard bytes.count <= available else {
                throw LCPluginError("Mach-O 头部空间不足，无法安全添加插件或扩展依赖路径。请使用预留了 header padding 的构建；原 IPA 未被修改。")
            }
            if bytes.count > oldSize {
                let padding = data[(slice.offset + 32 + oldSize)..<(slice.offset + 32 + bytes.count)]
                guard padding.allSatisfy({ $0 == 0 }) else { throw LCPluginError("Mach-O 头部后存在非空数据，已停止以避免覆盖程序。") }
            }
            let start = slice.offset + 32
            let regionSize = max(oldSize, bytes.count)
            output.replaceSubrange(start..<(start + regionSize), with: bytes + Data(repeating: 0, count: regionSize - bytes.count))
            output.put(UInt32(revised.count), at: slice.offset + 16)
            output.put(UInt32(bytes.count), at: slice.offset + 20)
        }
        data = output
    }

    public func write(to url: URL) throws { try data.write(to: url, options: .atomic) }

    private func commands(_ slice: Slice) throws -> [Command] {
        let count = Int(try data.word(slice.offset + 16))
        let size = Int(try data.word(slice.offset + 20))
        guard size <= slice.size - 32, count <= size / 8 else { throw LCPluginError("Mach-O 加载命令长度无效。") }
        var p = slice.offset + 32
        let end = p + size
        var result: [Command] = []
        for _ in 0..<count {
            guard p + 8 <= end else { throw LCPluginError("Mach-O 加载命令被截断。") }
            let type = try data.word(p)
            let length = Int(try data.word(p + 4))
            guard length >= 8, length % commandAlignment == 0, length <= end - p else { throw LCPluginError("Mach-O 加载命令格式错误。") }
            result.append(Command(type: type, bytes: data.subdata(in: p..<(p + length))))
            p += length
        }
        guard p == end else { throw LCPluginError("Mach-O 加载命令数量不匹配。") }
        return result
    }

    private func path(_ command: Command) throws -> String {
        guard command.bytes.count >= 24 else { throw LCPluginError("Mach-O 动态库路径被截断。") }
        let offset = Int(try command.bytes.word(8))
        guard offset >= 24, offset < command.bytes.count,
              let end = command.bytes[offset...].firstIndex(of: 0),
              let string = String(data: command.bytes[offset..<end], encoding: .utf8) else {
            throw LCPluginError("Mach-O 动态库路径损坏。")
        }
        return string
    }

    private func replacingPath(_ command: Command, with name: String) throws -> Command {
        guard !name.isEmpty, !name.contains("\0"), name.utf8.count < 4096 else { throw LCPluginError("动态库路径无效或过长。") }
        var bytes = Data(command.bytes.prefix(24))
        guard bytes.count == 24 else { throw LCPluginError("动态库加载命令被截断。") }
        bytes.append(contentsOf: name.utf8); bytes.append(0)
        bytes.append(Data(repeating: 0, count: (8 - bytes.count % 8) % 8))
        bytes.put(UInt32(bytes.count), at: 4); bytes.put(24, at: 8)
        return Command(type: command.type, bytes: bytes)
    }

    private func capacity(_ slice: Slice, commands: [Command]) throws -> Int {
        var first = slice.size
        for command in commands where command.type == 0x19 {
            let d = command.bytes
            guard d.count >= 72 else { throw LCPluginError("Mach-O segment 被截断。") }
            let fileoff = try d.long(40), filesize = try d.long(48)
            guard fileoff <= UInt64(slice.size), filesize <= UInt64(slice.size) - fileoff else { throw LCPluginError("Mach-O segment 越界。") }
            if fileoff > 0, filesize > 0 { first = min(first, Int(fileoff)) }
            let count = Int(try d.word(64))
            guard count <= (d.count - 72) / 80 else { throw LCPluginError("Mach-O section 数量无效。") }
            for i in 0..<count {
                let s = 72 + i * 80
                let offset = Int(try d.word(s + 48))
                let flags = try d.word(s + 64) & 0xff
                let size = try d.long(s + 40)
                if offset > 0, size > 0, ![UInt32(1), 0xc, 0x12].contains(flags) {
                    guard offset <= slice.size, size <= UInt64(slice.size - offset) else { throw LCPluginError("Mach-O section 越界。") }
                    first = min(first, offset)
                }
            }
        }
        let oldSize = Int(try data.word(slice.offset + 20))
        guard first < slice.size, first >= 32 + oldSize else { throw LCPluginError("无法确定 Mach-O 可安全修改的头部空间。") }
        return first - 32
    }
}

extension Data {
    func word(_ offset: Int, big: Bool = false) throws -> UInt32 {
        guard offset >= 0, count >= 4, offset <= count - 4 else { throw LCPluginError("二进制数据被截断。") }
        return (0..<4).reduce(0) { $0 | UInt32(self[offset + $1]) << (8 * (big ? 3 - $1 : $1)) }
    }
    func long(_ offset: Int, big: Bool = false) throws -> UInt64 {
        let a = UInt64(try word(offset, big: big)), b = UInt64(try word(offset + 4, big: big))
        return big ? a << 32 | b : a | b << 32
    }
    mutating func put(_ value: UInt32, at offset: Int) {
        for i in 0..<4 { self[offset + i] = UInt8(truncatingIfNeeded: value >> (8 * i)) }
    }
}
