import Foundation

/// Log and small state files in the shared App Group container: the packet
/// tunnel extension is a separate process from the app, so this is how the app
/// shows what the extension is doing.
enum SharedLog {
    static let groupID = "group.com.shndo1337.openfluxmail"
    private static let maxBytes = 256 * 1024

    private static var dir: URL? {
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: groupID)
    }
    private static var logURL: URL? { dir?.appendingPathComponent("tunnel.log") }
    private static var carrierURL: URL? { dir?.appendingPathComponent("carrier.state") }

    private static let queue = DispatchQueue(label: "sharedlog")

    static func write(_ line: String) {
        queue.async {
            guard let url = logURL else { return }
            let ts = ISO8601DateFormatter().string(from: Date())
            guard let data = "\(ts) \(line)\n".data(using: .utf8) else { return }
            let fm = FileManager.default
            if fm.fileExists(atPath: url.path) {
                if let size = (try? fm.attributesOfItem(atPath: url.path))?[.size] as? Int,
                   size > maxBytes,
                   let old = try? Data(contentsOf: url) {
                    try? old.suffix(maxBytes / 2).write(to: url)
                }
                if let handle = try? FileHandle(forWritingTo: url) {
                    handle.seekToEndOfFile()
                    handle.write(data)
                    try? handle.close()
                }
            } else {
                try? data.write(to: url)
            }
        }
    }

    static func clear() {
        queue.async {
            guard let url = logURL else { return }
            try? Data().write(to: url)
        }
    }

    static func read() -> String {
        queue.sync {
            guard let url = logURL, let data = try? Data(contentsOf: url) else { return "" }
            return String(data: data.suffix(40_000), encoding: .utf8) ?? ""
        }
    }

    /// True while the extension's carrier (the document) is connected.
    static var carrierUp: Bool {
        get {
            guard let url = carrierURL, let data = try? Data(contentsOf: url),
                  let s = String(data: data, encoding: .utf8) else { return false }
            return s == "1"
        }
        set {
            guard let url = carrierURL else { return }
            try? (newValue ? "1" : "0").data(using: .utf8)?.write(to: url)
        }
    }
}
