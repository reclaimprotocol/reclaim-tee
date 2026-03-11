/// iOS-specific native network implementation using method channels
///
/// This implementation bridges to the Swift NativeNetworkHandler class
/// which uses NWConnection for VPN-compatible networking.
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:flutter/services.dart';

import 'native_network_ffi.dart';

/// iOS implementation of [NativeConnectionHandler] using method channels
///
/// This bridges to the Swift NativeNetworkHandler which uses Network.framework
/// (NWConnection) for iOS networking that properly respects VPN tunnels.
///
/// **Note:** This synchronous implementation is not usable because iOS networking
/// is inherently asynchronous. Use [IOSNativeConnectionHandlerAsync] instead,
/// which pre-establishes connections before the protocol runs.
class IOSNativeConnectionHandler implements NativeConnectionHandler {
  @override
  NativeConnHandle connect(int connType, String url, int timeoutMs) {
    // This is called synchronously from the C callback, so we need
    // to use a synchronous approach or pre-establish connections.
    //
    // For a real implementation, you would need to either:
    // 1. Use Dart FFI to call Swift directly (complex)
    // 2. Pre-establish connections before the protocol runs
    // 3. Use isolates with synchronous communication
    //
    // This example shows the structure - see the note below for
    // how to properly implement this.

    throw UnimplementedError(
      'Direct FFI callbacks require synchronous Swift bridging. '
      'See IOSNativeConnectionHandlerAsync for the recommended approach.',
    );
  }

  @override
  Uint8List? read(NativeConnHandle handle, int maxBytes, int timeoutMs) {
    throw UnimplementedError('See IOSNativeConnectionHandlerAsync');
  }

  @override
  int write(NativeConnHandle handle, Uint8List data) {
    throw UnimplementedError('See IOSNativeConnectionHandlerAsync');
  }

  @override
  void close(NativeConnHandle handle) {
    throw UnimplementedError('See IOSNativeConnectionHandlerAsync');
  }
}

/// Asynchronous iOS native connection handler
///
/// Since Dart FFI callbacks must be synchronous but iOS networking is
/// inherently async, this handler pre-establishes connections and manages
/// them through method channels.
///
/// Usage:
/// ```dart
/// final handler = IOSNativeConnectionHandlerAsync();
///
/// // Pre-connect before starting protocol
/// await handler.preConnect(
///   teekUrl: 'wss://teek.reclaimprotocol.org/ws',
///   teetUrl: 'wss://teet.reclaimprotocol.org/ws',
///   targetHost: 'api.example.com',
///   targetPort: 443,
/// );
///
/// // Enable native networking with the handler's callbacks
/// handler.enable();
///
/// // Run your protocol...
///
/// // Cleanup
/// handler.disable();
/// await handler.closeAll();
/// ```
class IOSNativeConnectionHandlerAsync {
  static const _channel = MethodChannel('com.reclaim.native_network');

  final Map<String, int> _preConnectedHandles = {};
  bool _enabled = false;

  /// Pre-establish connections for the protocol
  ///
  /// Call this before enabling native networking to establish all required
  /// connections through iOS's VPN-compatible networking stack.
  ///
  /// If any connection fails, all previously established connections in this
  /// call will be cleaned up before the error is thrown.
  Future<void> preConnect({
    required String teekUrl,
    required String teetUrl,
    required String targetHost,
    required int targetPort,
  }) async {
    try {
      // Connect to TEE_K
      final teekHandle = await _connect(ConnectionType.websocket, teekUrl, 30000);
      _preConnectedHandles['teek'] = teekHandle;

      // Connect to TEE_T
      final teetHandle = await _connect(ConnectionType.websocket, teetUrl, 30000);
      _preConnectedHandles['teet'] = teetHandle;

      // Connect to target
      final targetHandle = await _connect(
        ConnectionType.tcp,
        '$targetHost:$targetPort',
        5000,
      );
      _preConnectedHandles['target'] = targetHandle;
    } catch (e) {
      // Clean up any connections that were successfully established
      await _cleanupOnError();
      rethrow;
    }
  }

  /// Clean up any established connections on error during preConnect
  Future<void> _cleanupOnError() async {
    for (final entry in _preConnectedHandles.entries.toList()) {
      try {
        await _channel.invokeMethod('close', {'handle': entry.value});
      } catch (_) {
        // Ignore errors during cleanup
      }
    }
    _preConnectedHandles.clear();
  }

  Future<int> _connect(int connType, String url, int timeoutMs) async {
    final result = await _channel.invokeMethod<Map>('connect', {
      'connType': connType,
      'url': url,
      'timeoutMs': timeoutMs,
    });

    final errorCode = result?['errorCode'] as int? ?? NativeNetError.unknown;
    if (errorCode != NativeNetError.success) {
      final message = result?['errorMessage'] as String? ?? 'Unknown error';
      throw NativeNetworkException(errorCode, message);
    }

    final handle = result?['handle'] as int?;
    if (handle == null || handle <= 0) {
      throw NativeNetworkException(
        NativeNetError.unknown,
        'Missing or invalid connection handle returned from native layer',
      );
    }

    return handle;
  }

  /// Read from a pre-connected handle
  Future<Uint8List?> read(String connectionName, int maxBytes, int timeoutMs) async {
    final handle = _preConnectedHandles[connectionName];
    if (handle == null) {
      throw NativeNetworkException(
        NativeNetError.closed,
        'Connection "$connectionName" not found',
      );
    }

    final result = await _channel.invokeMethod<Map>('read', {
      'handle': handle,
      'maxBytes': maxBytes,
      'timeoutMs': timeoutMs,
    });

    final errorCode = result?['errorCode'] as int? ?? NativeNetError.unknown;
    if (errorCode == NativeNetError.eof) {
      return null;
    }
    if (errorCode != NativeNetError.success) {
      throw NativeNetworkException(errorCode);
    }

    return result?['data'] as Uint8List?;
  }

  /// Write to a pre-connected handle
  Future<int> write(String connectionName, Uint8List data) async {
    final handle = _preConnectedHandles[connectionName];
    if (handle == null) {
      throw NativeNetworkException(
        NativeNetError.closed,
        'Connection "$connectionName" not found',
      );
    }

    final result = await _channel.invokeMethod<int>('write', {
      'handle': handle,
      'data': data,
    });

    if (result == null || result < 0) {
      throw NativeNetworkException(result ?? NativeNetError.unknown);
    }

    return result;
  }

  /// Close a specific connection
  Future<void> close(String connectionName) async {
    final handle = _preConnectedHandles.remove(connectionName);
    if (handle != null) {
      await _channel.invokeMethod('close', {'handle': handle});
    }
  }

  /// Close all connections
  ///
  /// Continues closing remaining connections even if one fails.
  Future<void> closeAll() async {
    for (final handle in _preConnectedHandles.values.toList()) {
      try {
        await _channel.invokeMethod('close', {'handle': handle});
      } catch (_) {
        // Continue closing other connections even if one fails
      }
    }
    _preConnectedHandles.clear();
  }

  /// Enable native networking mode
  ///
  /// This method tracks the enabled state for this handler. The actual FFI
  /// callback registration with the Go library should be done separately via
  /// [NativeNetworkManager.enable] after setting up a connection handler.
  void enable() {
    if (_enabled) return;
    _enabled = true;
  }

  /// Disable native networking
  void disable() {
    if (!_enabled) return;
    _enabled = false;
  }
}

/// Platform-specific native network handler factory
///
/// Note: On iOS, direct FFI callbacks require synchronous Swift bridging which
/// is complex to implement. The recommended approach is to use
/// [IOSNativeConnectionHandlerAsync] with pre-established connections instead.
///
/// This factory returns null because the synchronous [IOSNativeConnectionHandler]
/// is not fully implemented. Use [IOSNativeConnectionHandlerAsync] directly for
/// iOS native networking with VPN support.
NativeConnectionHandler? createPlatformHandler() {
  // The synchronous IOSNativeConnectionHandler is not implemented because
  // iOS networking (NWConnection) is inherently async. Use
  // IOSNativeConnectionHandlerAsync with preConnect() instead.
  //
  // Android and desktop platforms would have their own implementations.
  return null;
}
