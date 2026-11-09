// Sleep/wake and screen lock/unlock observers. Both notification centers deliver through the main
// thread's run loop only (measured: an observer added on a thread running its own CFRunLoop gets
// nothing), so events arrive while the main thread runs AppKit's or Slint's event loop.

import AppKit
import Foundation

public typealias PowerCallback = @convention(c) (UnsafeMutableRawPointer?, Int32) -> Void

// Mirrored in power.rs.
private let eventWillSleep: Int32 = 0
private let eventDidWake: Int32 = 1
private let eventScreenLocked: Int32 = 2
private let eventScreenUnlocked: Int32 = 3

private let screenLocked = Notification.Name("com.apple.screenIsLocked")
private let screenUnlocked = Notification.Name("com.apple.screenIsUnlocked")

private final class PowerObserver: NSObject {
  private let lock = NSLock()
  private var callback: PowerCallback?
  private let context: UnsafeMutableRawPointer?

  init(callback: @escaping PowerCallback, context: UnsafeMutableRawPointer?) {
    self.callback = callback
    self.context = context
    super.init()
    let workspace = NSWorkspace.shared.notificationCenter
    workspace.addObserver(
      self, selector: #selector(willSleep), name: NSWorkspace.willSleepNotification, object: nil)
    workspace.addObserver(
      self, selector: #selector(didWake), name: NSWorkspace.didWakeNotification, object: nil)
    // AppKit holds back distributed notifications while the app is inactive, which a tray app
    // nearly always is; without deliverImmediately a lock would surface on the next activation.
    let distributed = DistributedNotificationCenter.default()
    distributed.addObserver(
      self, selector: #selector(locked), name: screenLocked, object: nil,
      suspensionBehavior: .deliverImmediately)
    distributed.addObserver(
      self, selector: #selector(unlocked), name: screenUnlocked, object: nil,
      suspensionBehavior: .deliverImmediately)
  }

  @objc private func willSleep(_ notification: Notification) { emit(eventWillSleep) }
  @objc private func didWake(_ notification: Notification) { emit(eventDidWake) }
  @objc private func locked(_ notification: Notification) { emit(eventScreenLocked) }
  @objc private func unlocked(_ notification: Notification) { emit(eventScreenUnlocked) }

  // Holding the lock while calling out lets stop() guarantee no callback still runs once it
  // returns, so Rust may free the context right after.
  private func emit(_ event: Int32) {
    lock.lock()
    defer { lock.unlock() }
    callback?(context, event)
  }

  func stop() {
    lock.lock()
    callback = nil
    lock.unlock()
    NSWorkspace.shared.notificationCenter.removeObserver(self)
    DistributedNotificationCenter.default().removeObserver(self)
  }
}

@_cdecl("vk_power_subscribe")
public func vkPowerSubscribe(_ callback: PowerCallback, _ context: UnsafeMutableRawPointer?)
  -> UnsafeMutableRawPointer
{
  Unmanaged.passRetained(PowerObserver(callback: callback, context: context)).toOpaque()
}

@_cdecl("vk_power_unsubscribe")
public func vkPowerUnsubscribe(_ token: UnsafeMutableRawPointer) {
  Unmanaged<PowerObserver>.fromOpaque(token).takeRetainedValue().stop()
}

/// Posts a sleep (`sleep == true`) or wake notification on this process's workspace center only,
/// so tests can drive the observer without sleeping the machine. Dead-stripped from apps.
@_cdecl("vk_power_post_workspace_for_test")
public func vkPowerPostWorkspaceForTest(_ sleep: Bool) {
  let name = sleep ? NSWorkspace.willSleepNotification : NSWorkspace.didWakeNotification
  NSWorkspace.shared.notificationCenter.post(name: name, object: nil)
}
