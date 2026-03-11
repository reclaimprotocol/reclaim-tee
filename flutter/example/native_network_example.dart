/// Example: Using Native Networking for iOS VPN Compatibility
///
/// This example demonstrates how to enable and use native networking
/// in the Reclaim SDK to ensure connections work through iOS VPNs.
///
/// The problem: Go's network stack uses raw POSIX sockets which bypass
/// iOS VPN tunnels, causing "no route to host" errors for users on VPN.
///
/// The solution: Delegate network connections to iOS's Network.framework
/// (NWConnection) which properly respects VPN tunnel routing.
library;

import 'dart:io';

// In a real implementation, these would be your actual imports:
// import 'package:reclaim_sdk/native_network_ffi.dart';
// import 'package:reclaim_sdk/ios_native_network.dart';
// import 'package:reclaim_sdk/reclaim.dart';

/// Example 1: Basic Usage with Direct FFI (Advanced)
///
/// This approach uses direct FFI callbacks. It requires implementing
/// synchronous networking which is complex on iOS.
void exampleDirectFFI() {
  print('=== Example 1: Direct FFI Approach ===\n');

  print('''
// 1. Create your connection handler implementation
final handler = MyNativeConnectionHandler();

// 2. Configure the manager with your handler
NativeNetworkManager.instance.connectionHandler = handler;

// 3. Enable native networking
final success = NativeNetworkManager.instance.enable();
print('Native networking enabled: \$success');

// 4. Run your protocol - connections now go through native iOS networking
final result = await ReclaimSDK.executeProtocol(request);

// 5. Disable when done (optional)
NativeNetworkManager.instance.disable();
''');
}

/// Example 2: Recommended Approach - Pre-established Connections
///
/// Since iOS networking is inherently async but C callbacks must be
/// synchronous, the recommended approach is to pre-establish connections.
void examplePreEstablished() {
  print('=== Example 2: Pre-established Connections (Recommended) ===\n');

  print('''
// This approach pre-establishes all connections before the protocol runs,
// allowing the connections to be created asynchronously through iOS APIs.

class VPNSafeReclaimClient {
  final IOSNativeConnectionHandlerAsync _handler;

  VPNSafeReclaimClient() : _handler = IOSNativeConnectionHandlerAsync();

  Future<ReclaimResult> executeProtocol(ReclaimRequest request) async {
    try {
      // 1. Pre-establish all connections through iOS native networking
      //    These go through VPN because they use NWConnection
      await _handler.preConnect(
        teekUrl: 'wss://teek.reclaimprotocol.org/ws',
        teetUrl: 'wss://teet.reclaimprotocol.org/ws',
        targetHost: request.targetHost,
        targetPort: request.targetPort,
      );

      // 2. Enable native networking mode
      _handler.enable();

      // 3. Execute the protocol
      //    The Go code will use the pre-established connections
      final result = await ReclaimSDK.executeProtocol(request);

      return result;
    } finally {
      // 4. Clean up
      _handler.disable();
      await _handler.closeAll();
    }
  }
}

// Usage:
final client = VPNSafeReclaimClient();
final result = await client.executeProtocol(myRequest);
''');
}

/// Example 3: Checking VPN Status
///
/// You might want to only enable native networking when VPN is active,
/// since it adds overhead.
void exampleVPNDetection() {
  print('=== Example 3: Conditional VPN Detection ===\n');

  print('''
import 'package:network_info_plus/network_info_plus.dart';

class SmartReclaimClient {
  /// Check if device is likely using a VPN
  Future<bool> isVPNActive() async {
    if (!Platform.isIOS) return false;

    // On iOS, we can check for VPN by looking at network interfaces
    // This is a simplified check - production code should be more robust
    try {
      final interfaces = await NetworkInterface.list();
      for (final interface in interfaces) {
        // VPN interfaces often have names like 'utun0', 'ipsec0', etc.
        if (interface.name.startsWith('utun') ||
            interface.name.startsWith('ipsec') ||
            interface.name.startsWith('ppp')) {
          return true;
        }
      }
    } catch (e) {
      // If we can't check, assume VPN might be active for safety
      return true;
    }
    return false;
  }

  Future<ReclaimResult> executeProtocol(ReclaimRequest request) async {
    final useNativeNetworking = await isVPNActive();

    if (useNativeNetworking) {
      print('VPN detected - using native networking');
      return _executeWithNativeNetworking(request);
    } else {
      print('No VPN detected - using standard networking');
      return ReclaimSDK.executeProtocol(request);
    }
  }

  Future<ReclaimResult> _executeWithNativeNetworking(ReclaimRequest request) async {
    final handler = IOSNativeConnectionHandlerAsync();
    try {
      await handler.preConnect(...);
      handler.enable();
      return await ReclaimSDK.executeProtocol(request);
    } finally {
      handler.disable();
      await handler.closeAll();
    }
  }
}
''');
}

/// Example 4: Error Handling
void exampleErrorHandling() {
  print('=== Example 4: Error Handling ===\n');

  print('''
Future<ReclaimResult> executeWithRetry(ReclaimRequest request) async {
  // First attempt with standard networking
  try {
    return await ReclaimSDK.executeProtocol(request);
  } on SocketException catch (e) {
    // Check for VPN-related errors
    if (e.message.contains('No route to host') ||
        e.message.contains('Network is unreachable')) {
      print('Network error detected, retrying with native networking...');

      // Retry with native networking
      return await _executeWithNativeNetworking(request);
    }
    rethrow;
  }
}

Future<ReclaimResult> _executeWithNativeNetworking(ReclaimRequest request) async {
  final handler = IOSNativeConnectionHandlerAsync();

  try {
    await handler.preConnect(
      teekUrl: 'wss://teek.reclaimprotocol.org/ws',
      teetUrl: 'wss://teet.reclaimprotocol.org/ws',
      targetHost: request.targetHost,
      targetPort: request.targetPort,
    );

    handler.enable();
    return await ReclaimSDK.executeProtocol(request);

  } on NativeNetworkException catch (e) {
    switch (e.errorCode) {
      case NativeNetError.timeout:
        throw TimeoutException('Connection timed out');
      case NativeNetError.connectFailed:
        throw SocketException('Failed to connect: \${e.message}');
      case NativeNetError.closed:
        throw StateError('Connection was closed unexpectedly');
      default:
        throw Exception('Native network error: \${e.message}');
    }
  } finally {
    handler.disable();
    await handler.closeAll();
  }
}
''');
}

/// Example 5: Full Integration with Reclaim SDK
void exampleFullIntegration() {
  print('=== Example 5: Full Integration ===\n');

  print('''
import 'package:reclaim_sdk/reclaim_sdk.dart';
import 'package:reclaim_sdk/native_network_ffi.dart';
import 'package:reclaim_sdk/ios_native_network.dart';

class ReclaimService {
  static final ReclaimService instance = ReclaimService._();
  ReclaimService._();

  IOSNativeConnectionHandlerAsync? _nativeHandler;

  /// Execute a claim with automatic VPN handling
  Future<ClaimResult> executeClaim({
    required String providerName,
    required Map<String, dynamic> params,
    Map<String, dynamic>? secretParams,
    bool forceNativeNetworking = false,
  }) async {
    final shouldUseNative = forceNativeNetworking ||
                            Platform.isIOS && await _isVPNActive();

    if (shouldUseNative) {
      return _executeWithNativeNetworking(
        providerName: providerName,
        params: params,
        secretParams: secretParams,
      );
    }

    return _executeStandard(
      providerName: providerName,
      params: params,
      secretParams: secretParams,
    );
  }

  Future<ClaimResult> _executeWithNativeNetworking({
    required String providerName,
    required Map<String, dynamic> params,
    Map<String, dynamic>? secretParams,
  }) async {
    _nativeHandler = IOSNativeConnectionHandlerAsync();

    try {
      // Pre-establish connections through iOS native networking
      await _nativeHandler!.preConnect(
        teekUrl: ReclaimConfig.teekUrl,
        teetUrl: ReclaimConfig.teetUrl,
        targetHost: params['targetHost'] ?? 'api.example.com',
        targetPort: params['targetPort'] ?? 443,
      );

      // Enable native mode
      _nativeHandler!.enable();

      // Execute the claim
      final request = ReclaimRequest(
        name: providerName,
        params: params,
        secretParams: secretParams,
      );

      return await ReclaimSDK.executeClaim(request);

    } finally {
      _nativeHandler?.disable();
      await _nativeHandler?.closeAll();
      _nativeHandler = null;
    }
  }

  Future<ClaimResult> _executeStandard({
    required String providerName,
    required Map<String, dynamic> params,
    Map<String, dynamic>? secretParams,
  }) async {
    final request = ReclaimRequest(
      name: providerName,
      params: params,
      secretParams: secretParams,
    );

    return await ReclaimSDK.executeClaim(request);
  }

  Future<bool> _isVPNActive() async {
    try {
      final interfaces = await NetworkInterface.list();
      return interfaces.any((i) =>
        i.name.startsWith('utun') ||
        i.name.startsWith('ipsec'));
    } catch (_) {
      return false;
    }
  }
}

// Usage in your app:
void main() async {
  final result = await ReclaimService.instance.executeClaim(
    providerName: 'github-username',
    params: {'username': 'myuser'},
    secretParams: {'token': 'secret'},
  );

  print('Claim result: \${result.claim.identifier}');
}
''');
}

void main() {
  print('Native Network Examples for iOS VPN Compatibility\n');
  print('=' * 60);
  print('\n');

  exampleDirectFFI();
  print('\n');

  examplePreEstablished();
  print('\n');

  exampleVPNDetection();
  print('\n');

  exampleErrorHandling();
  print('\n');

  exampleFullIntegration();

  print('\n' + '=' * 60);
  print('\nKey Points:');
  print('1. Native networking delegates connections to iOS Network.framework');
  print('2. NWConnection respects VPN tunnel routing (unlike raw sockets)');
  print('3. Use pre-established connections for async iOS API compatibility');
  print('4. Consider detecting VPN to only enable when needed');
  print('5. Always clean up with disable() and closeAll()');
}
