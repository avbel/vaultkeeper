// Network path changes (Wi-Fi joined, VPN up, cable plugged in) through NWPathMonitor. Unlike the
// power notifications it delivers on its own dispatch queue, so no run loop is needed.

import Foundation
import Network

public typealias NetworkCallback = @convention(c) (UnsafeMutableRawPointer?, Int32) -> Void

// Mirrored in network.rs.
private let pathUnsatisfied: Int32 = 0
private let pathSatisfied: Int32 = 1

private final class NetworkObserver {
  private let lock = NSLock()
  private var callback: NetworkCallback?
  private let context: UnsafeMutableRawPointer?
  private let monitor = NWPathMonitor()

  init(callback: @escaping NetworkCallback, context: UnsafeMutableRawPointer?) {
    self.callback = callback
    self.context = context
    monitor.pathUpdateHandler = { [weak self] path in
      self?.emit(path.status == .satisfied ? pathSatisfied : pathUnsatisfied)
    }
    monitor.start(queue: DispatchQueue(label: "vaultkeeper.network"))
  }

  // Holding the lock while calling out lets stop() guarantee no callback still runs once it
  // returns, so Rust may free the context right after.
  private func emit(_ code: Int32) {
    lock.lock()
    defer { lock.unlock() }
    callback?(context, code)
  }

  func stop() {
    lock.lock()
    callback = nil
    lock.unlock()
    monitor.cancel()
  }
}

@_cdecl("vk_network_subscribe")
public func vkNetworkSubscribe(_ callback: NetworkCallback, _ context: UnsafeMutableRawPointer?)
  -> UnsafeMutableRawPointer
{
  Unmanaged.passRetained(NetworkObserver(callback: callback, context: context)).toOpaque()
}

@_cdecl("vk_network_unsubscribe")
public func vkNetworkUnsubscribe(_ token: UnsafeMutableRawPointer) {
  Unmanaged<NetworkObserver>.fromOpaque(token).takeRetainedValue().stop()
}
