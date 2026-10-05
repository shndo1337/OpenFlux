import NetworkExtension

/// System VPN entry point. Bridges the device's IP packets to the OpenFlux Go
/// tun2socks stack (TCP forwarded through the transport; DNS proxied over TCP).
class PacketTunnelProvider: NEPacketTunnelProvider {

    /// Networks that must NOT go through the tunnel: the Yandex backend the
    /// transport talks to, plus the DoT DNS resolvers. Otherwise the
    /// extension's own traffic loops back into itself.
    static let bypassRoutes: [NEIPv4Route] = {
        let cidrs: [(String, String)] = [
            ("5.45.192.0", "255.255.192.0"),
            ("5.255.192.0", "255.255.192.0"),
            ("37.9.64.0", "255.255.192.0"),
            ("37.140.128.0", "255.255.192.0"),
            ("77.88.0.0", "255.255.192.0"),
            ("84.201.128.0", "255.255.192.0"),
            ("87.250.224.0", "255.255.224.0"),
            ("90.156.176.0", "255.255.252.0"),
            ("93.158.128.0", "255.255.192.0"),
            ("95.108.128.0", "255.255.128.0"),
            ("100.43.64.0", "255.255.224.0"),
            ("178.154.128.0", "255.255.128.0"),
            ("213.180.192.0", "255.255.224.0"),
            // Mail.ru / VK cloud: cloud.mail.ru and docs.datacloudmail.ru, the
            // Mail.ru Docs carrier, live inside 95.163.0.0/16.
            ("95.163.0.0", "255.255.0.0"),
            // DoT DNS resolvers used by the Go client.
            ("8.8.8.8", "255.255.255.255"),
            ("1.1.1.1", "255.255.255.255"),
        ]
        return cidrs.map { NEIPv4Route(destinationAddress: $0.0, subnetMask: $0.1) }
    }()

    /// Carrier hosts resolved on the device before the tunnel is up (DNS can
    /// answer differently here than from a server), each excluded as a /32 so a
    /// carrier connection never goes back into the tunnel.
    static let carrierHosts = ["cloud.mail.ru", "docs.datacloudmail.ru"]

    static func resolveIPv4(_ host: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else { return [] }
        defer { freeaddrinfo(first) }
        var out: [String] = []
        var cur: UnsafeMutablePointer<addrinfo>? = first
        while let ai = cur {
            if let sa = ai.pointee.ai_addr, ai.pointee.ai_family == AF_INET {
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var addr = sin.pointee.sin_addr
                    inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
                }
                let ip = String(cString: buf)
                if !ip.isEmpty && !out.contains(ip) { out.append(ip) }
            }
            cur = ai.pointee.ai_next
        }
        return out
    }


    private var monitor: DispatchSourceTimer?
    private var ticks = 0
    private var lastUp: Bool?
    private var everUp = false

    private func footprintMB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size) / 4
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576 : -1
    }

    /// Once a second: moves the Go core's log into the shared file, mirrors the
    /// carrier state for the app and for iOS (reasserting), logs memory.
    private func startMonitor() {
        let t = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "monitor"))
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        monitor = t
    }

    private func tick() {
        ticks += 1
        if let c = OpenFluxReadLog() {
            let s = String(cString: c)
            OpenFluxFreeString(c)
            for line in s.split(separator: "\n") where !line.isEmpty {
                SharedLog.write(String(line))
            }
        }
        let up = OpenFluxPacketTunnelConnected() != 0
        if up != lastUp {
            lastUp = up
            SharedLog.carrierUp = up
            SharedLog.write("[EXT] carrier \(up ? "UP" : "DOWN")")
            if up { everUp = true }
            if everUp { reasserting = !up }
        }
        if ticks % 30 == 0 {
            SharedLog.write(String(format: "[EXT] heartbeat carrier=%@ mem=%.1fMB",
                                   up ? "up" : "down", footprintMB()))
        }
    }

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        SharedLog.clear()
        SharedLog.carrierUp = false
        let conf = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
        let transport = (conf["transport"] as? String) ?? "yandex"
        let url = (conf["url"] as? String) ?? ""
        let maxToken = (conf["maxToken"] as? String) ?? ""
        let maxUid = (conf["maxUid"] as? String) ?? ""
        let secret = (conf["secret"] as? String) ?? ""

        // Virtual interface: capture all IPv4 + all DNS.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // 10.10.10.2 is the address the exit node expects the client to use
        // (it hardcodes return packets to 10.10.10.2), enabling pure L3
        // forwarding with no gvisor stack in the extension.
        let ipv4 = NEIPv4Settings(addresses: ["10.10.10.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        // Exclude the transport's own backend (Yandex ranges) and the DoT DNS
        // servers so the extension's own connections bypass the tunnel instead
        // of looping back into it.
        var excluded = Self.bypassRoutes
        for host in Self.carrierHosts {
            for ip in Self.resolveIPv4(host) {
                excluded.append(NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255"))
            }
        }
        ipv4.excludedRoutes = excluded
        settings.ipv4Settings = ipv4
        settings.mtu = 1500
        // A benign in-tunnel DNS address: queries to it are captured and
        // answered locally over DoT (the real resolvers are excluded above).
        let dns = NEDNSSettings(servers: ["198.18.0.1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        setTunnelNetworkSettings(settings) { error in
            if let error = error {
                completionHandler(error)
                return
            }
            secret.withCString { OpenFluxSetEncryption(UnsafeMutablePointer(mutating: $0)) }
            let rc = transport.withCString { tt in
                url.withCString { u in
                    maxToken.withCString { tok in
                        maxUid.withCString { uid in
                            OpenFluxStartPacketTunnel(
                                UnsafeMutablePointer(mutating: tt),
                                UnsafeMutablePointer(mutating: u),
                                UnsafeMutablePointer(mutating: tok),
                                UnsafeMutablePointer(mutating: uid))
                        }
                    }
                }
            }
            SharedLog.write("[EXT] start transport=\(transport) rc=\(rc) encrypted=\(!secret.isEmpty)")
            if rc != 0 {
                completionHandler(NSError(domain: "OpenFlux", code: Int(rc),
                    userInfo: [NSLocalizedDescriptionKey: "start failed (\(rc))"]))
                return
            }
            self.startReadLoop()
            self.startWriteLoop()
            self.startMonitor()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        SharedLog.write("[EXT] stopTunnel reason=\(reason.rawValue) mem=\(Int(footprintMB()))MB")
        SharedLog.carrierUp = false
        monitor?.cancel()
        monitor = nil
        OpenFluxStopPacketTunnel()
        completionHandler()
    }

    /// Device -> Go stack.
    private func startReadLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self else { return }
            for p in packets {
                p.withUnsafeBytes { raw in
                    if let base = raw.bindMemory(to: CChar.self).baseAddress {
                        OpenFluxTunWritePacket(UnsafeMutablePointer(mutating: base), Int32(p.count))
                    }
                }
            }
            self.startReadLoop()
        }
    }

    /// Go stack -> device.
    private func startWriteLoop() {
        DispatchQueue.global(qos: .userInitiated).async {
            let maxLen: Int32 = 4096
            let buf = UnsafeMutablePointer<CChar>.allocate(capacity: Int(maxLen))
            defer { buf.deallocate() }
            while true {
                let n = OpenFluxTunReadPacket(buf, maxLen)
                if n <= 0 { break }
                let data = Data(bytes: buf, count: Int(n))
                self.packetFlow.writePackets([data], withProtocols: [NSNumber(value: AF_INET)])
            }
            SharedLog.write("[EXT] write loop ended")
        }
    }
}
