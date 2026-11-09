// C ABI shim over CryptoKit's Secure Enclave and LocalAuthentication. Raw pointers instead of
// swift-rs SRData keep the package free of the SwiftRs Swift dependency.

import CryptoKit
import CryptoTokenKit
import Foundation
import LocalAuthentication
import Security

private let statusOK: Int32 = 0
private let statusFailed: Int32 = 1
private let statusInvalidated: Int32 = 2
private let statusUnavailable: Int32 = 3
private let statusError: Int32 = 4

private let publicKeyLen = 65
private let sharedSecretLen = 32

// CryptoTokenKit codes compared as raw values: invalidatedDeviceKey (-10) exists only in macOS 27 SDKs.
private let tkUserFailureCodes: Set<Int> = [-4, -5, -9]
private let tkInvalidatedCodes: Set<Int> = [-3, -6, -7, -10]
private let osStatusUserFailureCodes: Set<Int> = [Int(errSecUserCanceled), Int(errSecAuthFailed)]
private let laUserFailureCodes: Set<Int> = [
  LAError.Code.authenticationFailed.rawValue,
  LAError.Code.userCancel.rawValue,
  LAError.Code.userFallback.rawValue,
  LAError.Code.systemCancel.rawValue,
  LAError.Code.appCancel.rawValue,
  LAError.Code.biometryLockout.rawValue,
  LAError.Code.notInteractive.rawValue,
]

private enum Failure {
  case user
  case invalidated
  case other
}

private func classify(_ error: Error) -> Failure {
  var current: NSError? = error as NSError
  while let err = current {
    switch err.domain {
    case LAErrorDomain where laUserFailureCodes.contains(err.code):
      return .user
    case LAErrorDomain where err.code == LAError.Code.biometryNotEnrolled.rawValue:
      return .invalidated
    case TKErrorDomain where tkUserFailureCodes.contains(err.code):
      return .user
    case TKErrorDomain where tkInvalidatedCodes.contains(err.code):
      return .invalidated
    case NSOSStatusErrorDomain where osStatusUserFailureCodes.contains(err.code):
      return .user
    default:
      current = err.userInfo[NSUnderlyingErrorKey] as? NSError
    }
  }
  return .other
}

private func writeDiag(_ error: Error, _ out: UnsafeMutablePointer<CChar>, _ cap: UInt) {
  let ns = error as NSError
  writeDiag("\(ns.domain) \(ns.code): \(ns.localizedDescription)", out, cap)
}

private func writeDiag(_ message: String, _ out: UnsafeMutablePointer<CChar>, _ cap: UInt) {
  guard cap > 0 else { return }
  let bytes = Array(message.utf8.prefix(Int(cap) - 1)) + [0]
  out.withMemoryRebound(to: UInt8.self, capacity: bytes.count) { dst in
    for (index, byte) in bytes.enumerated() {
      dst[index] = byte
    }
  }
}

/// Changes whenever fingerprints are added or removed; populated by a successful canEvaluatePolicy.
private func biometryState(_ context: LAContext) -> Data? {
  if #available(macOS 15.0, *) {
    return context.domainState.biometry.stateHash
  }
  return context.evaluatedPolicyDomainState
}

private func copy(_ data: Data, to out: UnsafeMutablePointer<UInt8>, cap: UInt) -> Bool {
  guard data.count <= Int(cap) else { return false }
  data.copyBytes(to: out, count: data.count)
  return true
}

@_cdecl("vk_se_is_available")
public func vkSeIsAvailable() -> Bool {
  SecureEnclave.isAvailable
    && LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
}

/// Creates a Secure Enclave P-256 key-agreement key usable only after a Touch ID match against
/// the currently enrolled fingers. Creation itself never prompts.
@_cdecl("vk_se_generate")
public func vkSeGenerate(
  _ blobOut: UnsafeMutablePointer<UInt8>, _ blobCap: UInt, _ blobLen: UnsafeMutablePointer<UInt>,
  _ publicKeyOut: UnsafeMutablePointer<UInt8>,
  _ stateOut: UnsafeMutablePointer<UInt8>, _ stateCap: UInt, _ stateLen: UnsafeMutablePointer<UInt>,
  _ diag: UnsafeMutablePointer<CChar>, _ diagCap: UInt
) -> Int32 {
  let context = LAContext()
  var laError: NSError?
  guard SecureEnclave.isAvailable,
    context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError)
  else {
    if let laError { writeDiag(laError, diag, diagCap) }
    return statusUnavailable
  }
  var cfError: Unmanaged<CFError>?
  guard
    let access = SecAccessControlCreateWithFlags(
      nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet],
      &cfError)
  else {
    if let cfError { writeDiag(cfError.takeRetainedValue(), diag, diagCap) }
    return statusError
  }
  do {
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      accessControl: access, authenticationContext: context)
    let publicKey = key.publicKey.x963Representation
    let state = biometryState(context) ?? Data()
    guard publicKey.count == publicKeyLen,
      copy(key.dataRepresentation, to: blobOut, cap: blobCap),
      copy(state, to: stateOut, cap: stateCap)
    else {
      writeDiag("output buffer too small", diag, diagCap)
      return statusError
    }
    publicKey.copyBytes(to: publicKeyOut, count: publicKeyLen)
    blobLen.pointee = UInt(key.dataRepresentation.count)
    stateLen.pointee = UInt(state.count)
    return statusOK
  } catch {
    writeDiag(error, diag, diagCap)
    return statusError
  }
}

private func enrolmentChanged(_ enrolled: Data, _ current: Data) -> Bool {
  !enrolled.isEmpty && !current.isEmpty && enrolled != current
}

/// Restoring the key from its blob failed. Only a definitive cause (fingers changed, key gone or
/// corrupt) invalidates, because the app then deletes the enrolment; anything else (Secure
/// Enclave busy, screen locked, an unknown error) is a plain failure that falls back to the
/// password and keeps the file for next time.
private func keyInitFailureStatus(_ error: Error, enrolledChanged: Bool) -> Int32 {
  if enrolledChanged { return statusInvalidated }
  switch classify(error) {
  case .invalidated: return statusInvalidated
  case .user: return statusFailed
  case .other: return statusError
  }
}

/// [keyInitFailureStatus] for an error of `domain`/`code`, optionally wrapping an underlying
/// `underlyingDomain`/`underlyingCode` (empty domain: none). Dead-stripped from apps.
@_cdecl("vk_se_key_init_status_for_test")
public func vkSeKeyInitStatusForTest(
  _ domain: UnsafePointer<CChar>, _ code: Int,
  _ underlyingDomain: UnsafePointer<CChar>, _ underlyingCode: Int,
  _ enrolledChanged: Bool
) -> Int32 {
  let underlying = String(cString: underlyingDomain)
  let userInfo: [String: Any] =
    underlying.isEmpty
    ? [:] : [NSUnderlyingErrorKey: NSError(domain: underlying, code: underlyingCode)]
  let error = NSError(domain: String(cString: domain), code: code, userInfo: userInfo)
  return keyInitFailureStatus(error, enrolledChanged: enrolledChanged)
}

/// ECDH between the Secure Enclave key in `blob` and `peer` (x9.63). Shows the Touch ID prompt
/// with `reason` and blocks until it is answered, so never call it on the UI thread.
@_cdecl("vk_se_ecdh")
public func vkSeEcdh(
  _ blob: UnsafePointer<UInt8>, _ blobLen: UInt,
  _ enrolledState: UnsafePointer<UInt8>, _ enrolledStateLen: UInt,
  _ peer: UnsafePointer<UInt8>, _ peerLen: UInt,
  _ reason: UnsafePointer<CChar>,
  _ secretOut: UnsafeMutablePointer<UInt8>,
  _ diag: UnsafeMutablePointer<CChar>, _ diagCap: UInt
) -> Int32 {
  let context = LAContext()
  context.localizedReason = String(cString: reason)
  var laError: NSError?
  guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError) else {
    guard let laError else { return statusUnavailable }
    writeDiag(laError, diag, diagCap)
    return laError.code == LAError.Code.biometryNotEnrolled.rawValue
      ? statusInvalidated : statusUnavailable
  }
  let enrolled = Data(bytes: enrolledState, count: Int(enrolledStateLen))
  let current = biometryState(context) ?? Data()

  let peerKey: P256.KeyAgreement.PublicKey
  do {
    peerKey = try P256.KeyAgreement.PublicKey(
      x963Representation: Data(bytes: peer, count: Int(peerLen)))
  } catch {
    writeDiag(error, diag, diagCap)
    return statusError
  }
  let key: SecureEnclave.P256.KeyAgreement.PrivateKey
  do {
    key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: Data(bytes: blob, count: Int(blobLen)), authenticationContext: context)
  } catch {
    writeDiag(error, diag, diagCap)
    return keyInitFailureStatus(error, enrolledChanged: enrolmentChanged(enrolled, current))
  }
  do {
    let secret = try key.sharedSecretFromKeyAgreement(with: peerKey)
    return secret.withUnsafeBytes { raw -> Int32 in
      guard raw.count == sharedSecretLen else {
        writeDiag("unexpected shared secret length \(raw.count)", diag, diagCap)
        return statusError
      }
      raw.copyBytes(to: UnsafeMutableRawBufferPointer(start: secretOut, count: sharedSecretLen))
      return statusOK
    }
  } catch {
    writeDiag(error, diag, diagCap)
    // A changed enrolment is definitive; error codes alone are not documented for this case.
    if enrolmentChanged(enrolled, current) {
      return statusInvalidated
    }
    switch classify(error) {
    case .user: return statusFailed
    case .invalidated: return statusInvalidated
    case .other: return statusError
    }
  }
}

/// Plain Touch ID check without a key. Blocks until the prompt is answered.
@_cdecl("vk_la_authenticate")
public func vkLaAuthenticate(
  _ reason: UnsafePointer<CChar>, _ diag: UnsafeMutablePointer<CChar>, _ diagCap: UInt
) -> Int32 {
  let context = LAContext()
  var laError: NSError?
  guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError) else {
    if let laError { writeDiag(laError, diag, diagCap) }
    return statusUnavailable
  }
  let done = DispatchSemaphore(value: 0)
  let result = AuthResult()
  context.evaluatePolicy(
    .deviceOwnerAuthenticationWithBiometrics, localizedReason: String(cString: reason)
  ) { success, error in
    result.status = success ? statusOK : statusFailed
    result.error = error
    done.signal()
  }
  done.wait()
  if let error = result.error {
    writeDiag(error, diag, diagCap)
    if case .other = classify(error) { return statusError }
  }
  return result.status
}

// The reply block runs on a private queue; the semaphore orders the write before the read.
private final class AuthResult: @unchecked Sendable {
  var status: Int32 = statusError
  var error: Error?
}
