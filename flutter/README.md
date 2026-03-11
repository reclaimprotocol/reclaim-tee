# Native Network Flutter Wrapper

This directory contains Flutter/Dart bindings for the iOS native network delegation feature, which allows the Reclaim SDK to work properly with iOS VPNs.

## Problem

Go's network stack in shared libraries uses raw POSIX sockets which bypass iOS VPN tunnels. Users on VPN experience "no route to host" errors because network traffic doesn't go through the VPN tunnel.

## Solution

This wrapper delegates network connections to iOS's Network.framework (`NWConnection`) which properly respects VPN tunnel routing.

## Architecture

```text
Flutter/iOS App (NWConnection - respects VPN)
        ↑↓ Method Channel / FFI
    Dart FFI Bindings
        ↑↓ C callbacks
Go Library (protocol logic, protobuf handling)
```

## Files

### Dart

- `lib/native_network_ffi.dart` - FFI type definitions and `NativeNetworkManager`
- `lib/ios_native_network.dart` - iOS-specific implementation using method channels

### iOS (Swift)

- `ios/Classes/NativeNetworkHandler.swift` - Native networking using `NWConnection`
- `ios/Classes/NativeNetworkPlugin.swift` - Flutter method channel handler

### Example

- `example/native_network_example.dart` - Usage examples

## Quick Start

### 1. Basic Usage

```dart
import 'package:reclaim_sdk/native_network_ffi.dart';
import 'package:reclaim_sdk/ios_native_network.dart';

// Create the async handler (recommended for iOS)
final handler = IOSNativeConnectionHandlerAsync();

// Pre-establish connections through iOS native networking
await handler.preConnect(
  teekUrl: 'wss://teek.reclaimprotocol.org/ws',
  teetUrl: 'wss://teet.reclaimprotocol.org/ws',
  targetHost: 'api.example.com',
  targetPort: 443,
);

// Enable native networking mode
handler.enable();

try {
  // Execute your protocol
  final result = await ReclaimSDK.executeProtocol(request);
  print('Success: ${result.claim.identifier}');
} finally {
  // Clean up
  handler.disable();
  await handler.closeAll();
}
```

### 2. With VPN Detection

```dart
Future<bool> isVPNActive() async {
  if (!Platform.isIOS) return false;

  final interfaces = await NetworkInterface.list();
  return interfaces.any((i) =>
    i.name.startsWith('utun') ||
    i.name.startsWith('ipsec'));
}

Future<ClaimResult> executeClaim(ReclaimRequest request) async {
  if (await isVPNActive()) {
    // Use native networking for VPN compatibility
    return executeWithNativeNetworking(request);
  } else {
    // Use standard networking (faster)
    return ReclaimSDK.executeProtocol(request);
  }
}
```

### 3. Error Handling

```dart
try {
  await handler.preConnect(...);
  // ...
} on NativeNetworkException catch (e) {
  switch (e.errorCode) {
    case NativeNetError.timeout:
      print('Connection timed out');
      break;
    case NativeNetError.connectFailed:
      print('Failed to connect: ${e.message}');
      break;
    case NativeNetError.closed:
      print('Connection closed unexpectedly');
      break;
  }
}
```

## API Reference

### Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `success` | Operation completed successfully |
| -1 | `unknown` | Unknown error |
| -2 | `timeout` | Operation timed out |
| -3 | `eof` | End of stream reached |
| -4 | `closed` | Connection is closed |
| -5 | `connectFailed` | Connection attempt failed |

### Connection Types

| Value | Name | Description |
|-------|------|-------------|
| 1 | `websocket` | WebSocket connection (ws:// or wss://) |
| 2 | `tcp` | Raw TCP connection |

## iOS Setup

### 1. Add to Podfile

```ruby
pod 'reclaim_native_network', :path => '../flutter/ios'
```

### 2. Register Plugin

In your `AppDelegate.swift`:

```swift
import reclaim_native_network

@UIApplicationMain
class AppDelegate: FlutterAppDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    // Register plugins
    GeneratedPluginRegistrant.register(with: self)

    // Register native network plugin
    let controller = window?.rootViewController as! FlutterViewController
    NativeNetworkPlugin.register(
      with: self.registrar(forPlugin: "NativeNetworkPlugin")!
    )

    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }
}
```

## How It Works

### Connection Flow

1. **Pre-connect Phase**: Dart calls method channel to establish connections via `NWConnection`
2. **Enable Phase**: FFI callbacks are registered with the Go library
3. **Protocol Phase**: Go code uses pre-established connections via callbacks
4. **Cleanup Phase**: Disable callbacks and close all connections

### Why Pre-established Connections?

C/FFI callbacks must be synchronous, but iOS networking (`NWConnection`) is inherently asynchronous. By pre-establishing connections before the protocol runs, we avoid the synchronous/async mismatch.

### Thread Safety

- Go library: Protected by mutexes (`nativeNetworkMutex`)
- Swift: Uses `NSLock` and dispatch queues
- Dart: Method channel handles serialization

## Troubleshooting

### "No route to host" errors

1. Check VPN is connected and working
2. Verify native networking is enabled before protocol execution
3. Ensure connections are pre-established

### Connection timeouts

1. Increase timeout values in `preConnect()`
2. Check network connectivity
3. Verify server URLs are correct

### Memory issues

Always call `closeAll()` in a finally block to clean up connections:

```dart
try {
  await handler.preConnect(...);
  // ...
} finally {
  await handler.closeAll();  // Always clean up!
}
```

## Performance Notes

- Native networking adds overhead compared to Go's direct sockets
- Only enable when VPN is detected to avoid unnecessary overhead
- Pre-established connections reduce latency during protocol execution

## License

Same license as the main reclaim-tee project.
