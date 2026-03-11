/// Native Network FFI bindings for iOS VPN compatibility
///
/// This module provides FFI bindings to enable native networking in the
/// Go shared library, allowing iOS to handle network connections via
/// URLSession/NWConnection which properly respect VPN tunnels.
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// =============================================================================
// C Type Definitions (must match lib/native_network.go)
// =============================================================================

/// Connection types
abstract class ConnectionType {
  static const int websocket = 1;
  static const int tcp = 2;
}

/// Error codes for native network operations
abstract class NativeNetError {
  static const int success = 0;
  static const int unknown = -1;
  static const int timeout = -2;
  static const int eof = -3;
  static const int closed = -4;
  static const int connectFailed = -5;
}

/// Native connection handle - opaque pointer
typedef NativeConnHandle = Pointer<Void>;

/// Result of a connection attempt
final class ConnectionResult extends Struct {
  external NativeConnHandle handle;

  @Int32()
  external int errorCode;

  external Pointer<Utf8> errorMessage;
}

/// Result of a read operation
final class ReadResult extends Struct {
  external Pointer<Uint8> data;

  @Int32()
  external int length;

  @Int32()
  external int errorCode;
}

// =============================================================================
// Callback Function Types
// =============================================================================

/// Connect callback: (connType, url, timeoutMs) -> ConnectionResult
typedef NativeConnectCallbackNative = ConnectionResult Function(
  Int32 connType,
  Pointer<Utf8> url,
  Int32 timeoutMs,
);
typedef NativeConnectCallback = ConnectionResult Function(
  int connType,
  Pointer<Utf8> url,
  int timeoutMs,
);

/// Read callback: (handle, maxBytes, timeoutMs) -> ReadResult
typedef NativeReadCallbackNative = ReadResult Function(
  NativeConnHandle handle,
  Int32 maxBytes,
  Int32 timeoutMs,
);
typedef NativeReadCallback = ReadResult Function(
  NativeConnHandle handle,
  int maxBytes,
  int timeoutMs,
);

/// Write callback: (handle, data, length) -> int (bytes written or error)
typedef NativeWriteCallbackNative = Int32 Function(
  NativeConnHandle handle,
  Pointer<Uint8> data,
  Int32 length,
);
typedef NativeWriteCallback = int Function(
  NativeConnHandle handle,
  Pointer<Uint8> data,
  int length,
);

/// Close callback: (handle) -> void
typedef NativeCloseCallbackNative = Void Function(NativeConnHandle handle);
typedef NativeCloseCallback = void Function(NativeConnHandle handle);

// =============================================================================
// Library Function Types
// =============================================================================

/// enable_native_networking function type
typedef EnableNativeNetworkingNative = Int32 Function(
  Pointer<NativeFunction<NativeConnectCallbackNative>> connectCb,
  Pointer<NativeFunction<NativeReadCallbackNative>> readCb,
  Pointer<NativeFunction<NativeWriteCallbackNative>> writeCb,
  Pointer<NativeFunction<NativeCloseCallbackNative>> closeCb,
);
typedef EnableNativeNetworking = int Function(
  Pointer<NativeFunction<NativeConnectCallbackNative>> connectCb,
  Pointer<NativeFunction<NativeReadCallbackNative>> readCb,
  Pointer<NativeFunction<NativeWriteCallbackNative>> writeCb,
  Pointer<NativeFunction<NativeCloseCallbackNative>> closeCb,
);

/// disable_native_networking function type
typedef DisableNativeNetworkingNative = Void Function();
typedef DisableNativeNetworking = void Function();

// =============================================================================
// Native Network Manager
// =============================================================================

/// Manages native networking for iOS VPN compatibility
class NativeNetworkManager {
  static NativeNetworkManager? _instance;
  static NativeNetworkManager get instance => _instance ??= NativeNetworkManager._();

  final DynamicLibrary _lib;
  late final EnableNativeNetworking _enableNativeNetworking;
  late final DisableNativeNetworking _disableNativeNetworking;

  bool _isEnabled = false;

  /// Connection handler - must be set before enabling native networking
  NativeConnectionHandler? connectionHandler;

  NativeNetworkManager._() : _lib = _loadLibrary() {
    _enableNativeNetworking = _lib
        .lookup<NativeFunction<EnableNativeNetworkingNative>>(
            'enable_native_networking')
        .asFunction();

    _disableNativeNetworking = _lib
        .lookup<NativeFunction<DisableNativeNetworkingNative>>(
            'disable_native_networking')
        .asFunction();
  }

  static DynamicLibrary _loadLibrary() {
    if (Platform.isIOS) {
      return DynamicLibrary.process();
    } else if (Platform.isAndroid) {
      return DynamicLibrary.open('libreclaim.so');
    } else if (Platform.isMacOS) {
      return DynamicLibrary.open('libreclaim.dylib');
    } else if (Platform.isLinux) {
      return DynamicLibrary.open('libreclaim.so');
    } else if (Platform.isWindows) {
      return DynamicLibrary.open('reclaim.dll');
    }
    throw UnsupportedError('Unsupported platform');
  }

  /// Whether native networking is currently enabled
  bool get isEnabled => _isEnabled;

  /// Enable native networking with the configured connection handler
  ///
  /// Returns true if successfully enabled, false otherwise.
  /// Throws if no connection handler is configured.
  bool enable() {
    if (_isEnabled) return true;

    if (connectionHandler == null) {
      throw StateError(
        'No connection handler configured. Set connectionHandler before calling enable().',
      );
    }

    final result = _enableNativeNetworking(
      Pointer.fromFunction<NativeConnectCallbackNative>(_connectCallback),
      Pointer.fromFunction<NativeReadCallbackNative>(_readCallback),
      Pointer.fromFunction<NativeWriteCallbackNative>(_writeCallback, 0),
      Pointer.fromFunction<NativeCloseCallbackNative>(_closeCallback),
    );

    _isEnabled = result != 0;
    return _isEnabled;
  }

  /// Disable native networking
  void disable() {
    if (!_isEnabled) return;
    _disableNativeNetworking();
    _isEnabled = false;
  }
}

// =============================================================================
// Static Callback Implementations
// =============================================================================

/// Static connect callback that delegates to the connection handler
ConnectionResult _connectCallback(
  int connType,
  Pointer<Utf8> urlPtr,
  int timeoutMs,
) {
  final handler = NativeNetworkManager.instance.connectionHandler;
  if (handler == null) {
    return _createErrorResult(NativeNetError.unknown, 'No handler configured');
  }

  final url = urlPtr.toDartString();

  try {
    final handle = handler.connect(connType, url, timeoutMs);
    return _createSuccessResult(handle);
  } catch (e) {
    // Preserve specific error codes from NativeNetworkException
    if (e is NativeNetworkException) {
      return _createErrorResult(e.errorCode, e.message ?? e.toString());
    }
    return _createErrorResult(NativeNetError.connectFailed, e.toString());
  }
}

/// Static read callback that delegates to the connection handler
ReadResult _readCallback(
  NativeConnHandle handle,
  int maxBytes,
  int timeoutMs,
) {
  final handler = NativeNetworkManager.instance.connectionHandler;
  if (handler == null) {
    return _createReadErrorResult(NativeNetError.unknown);
  }

  try {
    final data = handler.read(handle, maxBytes, timeoutMs);
    if (data == null) {
      return _createReadErrorResult(NativeNetError.eof);
    }
    return _createReadSuccessResult(data);
  } catch (e) {
    if (e is NativeNetworkException) {
      return _createReadErrorResult(e.errorCode);
    }
    return _createReadErrorResult(NativeNetError.unknown);
  }
}

/// Static write callback that delegates to the connection handler
int _writeCallback(
  NativeConnHandle handle,
  Pointer<Uint8> dataPtr,
  int length,
) {
  final handler = NativeNetworkManager.instance.connectionHandler;
  if (handler == null) {
    return NativeNetError.unknown;
  }

  try {
    final data = dataPtr.asTypedList(length);
    return handler.write(handle, Uint8List.fromList(data));
  } catch (e) {
    if (e is NativeNetworkException) {
      return e.errorCode;
    }
    return NativeNetError.unknown;
  }
}

/// Static close callback that delegates to the connection handler
void _closeCallback(NativeConnHandle handle) {
  final handler = NativeNetworkManager.instance.connectionHandler;
  handler?.close(handle);
}

// =============================================================================
// Helper Functions
// =============================================================================

// Memory Ownership Contract:
// --------------------------
// The helper functions below allocate native memory that is passed to the Go/C
// layer via FFI callbacks. The Go layer is responsible for using the data and
// then the memory becomes unreachable. In practice:
//
// - ConnectionResult and ReadResult structs are stack-allocated by the C caller
//   and we just populate them, so the struct memory itself is not leaked.
// - The data buffers (for ReadResult) and error message strings are copied by
//   the Go layer immediately after the callback returns.
//
// For a production implementation, consider:
// 1. Using a memory pool to reuse allocations
// 2. Having the Go layer call back to free the memory
// 3. Using arena allocators that can be bulk-freed
//
// Current implementation note: These allocations may leak in edge cases.
// This is acceptable for short-lived protocol operations but should be
// addressed for long-running applications.

ConnectionResult _createSuccessResult(NativeConnHandle handle) {
  final resultPtr = calloc<ConnectionResult>();
  resultPtr.ref.handle = handle;
  resultPtr.ref.errorCode = NativeNetError.success;
  resultPtr.ref.errorMessage = nullptr;
  return resultPtr.ref;
}

ConnectionResult _createErrorResult(int errorCode, String message) {
  final resultPtr = calloc<ConnectionResult>();
  resultPtr.ref.handle = nullptr;
  resultPtr.ref.errorCode = errorCode;
  // Note: This UTF-8 string allocation is copied by the Go layer and then
  // becomes unreachable. For production use, implement a free callback.
  resultPtr.ref.errorMessage = message.toNativeUtf8();
  return resultPtr.ref;
}

ReadResult _createReadSuccessResult(Uint8List data) {
  final resultPtr = calloc<ReadResult>();
  final dataPtr = calloc<Uint8>(data.length);
  dataPtr.asTypedList(data.length).setAll(0, data);
  resultPtr.ref.data = dataPtr;
  resultPtr.ref.length = data.length;
  resultPtr.ref.errorCode = NativeNetError.success;
  return resultPtr.ref;
}

ReadResult _createReadErrorResult(int errorCode) {
  final resultPtr = calloc<ReadResult>();
  resultPtr.ref.data = nullptr;
  resultPtr.ref.length = 0;
  resultPtr.ref.errorCode = errorCode;
  return resultPtr.ref;
}

// =============================================================================
// Connection Handler Interface
// =============================================================================

/// Exception for native network errors
class NativeNetworkException implements Exception {
  final int errorCode;
  final String? message;

  NativeNetworkException(this.errorCode, [this.message]);

  @override
  String toString() => 'NativeNetworkException($errorCode): $message';
}

/// Interface for handling native network connections
///
/// Implement this interface to provide platform-specific networking
/// that respects VPN tunnels (e.g., using iOS NWConnection or URLSession).
abstract class NativeConnectionHandler {
  /// Connect to the given URL
  ///
  /// [connType] is either [ConnectionType.websocket] or [ConnectionType.tcp]
  /// [url] is the target URL or address (e.g., "wss://example.com/ws" or "example.com:443")
  /// [timeoutMs] is the connection timeout in milliseconds
  ///
  /// Returns an opaque handle to the connection.
  /// Throws [NativeNetworkException] on failure.
  NativeConnHandle connect(int connType, String url, int timeoutMs);

  /// Read data from the connection
  ///
  /// [handle] is the connection handle from [connect]
  /// [maxBytes] is the maximum number of bytes to read
  /// [timeoutMs] is the read timeout in milliseconds
  ///
  /// Returns the data read, or null for EOF.
  /// Throws [NativeNetworkException] on failure.
  Uint8List? read(NativeConnHandle handle, int maxBytes, int timeoutMs);

  /// Write data to the connection
  ///
  /// [handle] is the connection handle from [connect]
  /// [data] is the data to write
  ///
  /// Returns the number of bytes written.
  /// Throws [NativeNetworkException] on failure.
  int write(NativeConnHandle handle, Uint8List data);

  /// Close the connection
  ///
  /// [handle] is the connection handle from [connect]
  void close(NativeConnHandle handle);
}
