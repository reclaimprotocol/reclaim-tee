import koffi from 'koffi';
import path from 'path';

// Error codes matching C enum
export enum ReclaimError {
  SUCCESS = 0,
  INVALID_ARGS = -1,
  CONNECTION_FAILED = -2,
  PROTOCOL_FAILED = -3,
  TIMEOUT = -4,
  MEMORY = -5,
  SESSION_NOT_FOUND = -6,
  ALREADY_COMPLETED = -7,
}

// Algorithm IDs for ZK circuits
export enum AlgorithmID {
  CHACHA20_OPRF = 3,
  AES_128_OPRF = 4,
  AES_256_OPRF = 5,
}

// Define GoSlice struct for passing byte arrays to Go
const GoSlice = koffi.struct('GoSlice', {
  data: 'void*',
  len: 'int64',
  cap: 'int64',
});

// Library instance
let lib: koffi.IKoffiLib | null = null;

// Function pointers
let _reclaim_execute_protocol: koffi.KoffiFunction | null = null;
let _reclaim_free_string: koffi.KoffiFunction | null = null;
let _reclaim_get_error_message: koffi.KoffiFunction | null = null;
let _reclaim_get_version: koffi.KoffiFunction | null = null;
let _init_algorithm: koffi.KoffiFunction | null = null;

/**
 * Get the architecture-specific library path
 */
function getDefaultLibraryPath(): string {
  const arch = process.arch;
  let archDir: string;

  switch (arch) {
    case 'x64':
      archDir = 'amd64';
      break;
    case 'arm64':
      archDir = 'arm64';
      break;
    default:
      throw new Error(`Unsupported architecture: ${arch}`);
  }

  return path.resolve(__dirname, '..', 'lib', archDir, 'libreclaim.so');
}

/**
 * Load the libreclaim shared library
 * @param libraryPath - Path to libreclaim.so (optional, auto-detects architecture if not provided)
 */
export function loadLibrary(libraryPath?: string): void {
  if (lib) {
    return; // Already loaded
  }

  const libPath = libraryPath || getDefaultLibraryPath();

  lib = koffi.load(libPath);

  // Define function signatures
  // reclaim_execute_protocol(char* request_json, char* config_json, char** claim_json, int* claim_length) -> int
  _reclaim_execute_protocol = lib.func('reclaim_execute_protocol', 'int', [
    'str',             // request_json
    'str',             // config_json
    '_Out_ void**',    // claim_json (output pointer - raw pointer for proper freeing)
    '_Out_ int*',      // claim_length (output pointer)
  ]);

  // reclaim_free_string(char* str) -> void
  _reclaim_free_string = lib.func('reclaim_free_string', 'void', ['void*']);

  // reclaim_get_error_message(int error) -> char*
  _reclaim_get_error_message = lib.func('reclaim_get_error_message', 'str', ['int']);

  // reclaim_get_version() -> char*
  _reclaim_get_version = lib.func('reclaim_get_version', 'str', []);

  // InitAlgorithm(uint8 algorithmID, GoSlice provingKey, GoSlice r1cs) -> uint8
  _init_algorithm = lib.func('InitAlgorithm', 'uint8', ['uint8', GoSlice, GoSlice]);
}

// Store for raw pointers that need to be freed
export type RawPointer = unknown;

/**
 * Execute the Reclaim protocol
 * @param requestJson - JSON string containing the request parameters
 * @param configJson - JSON string containing configuration (optional)
 * @returns Object with error code, claim JSON, and raw pointer for cleanup
 */
export function executeProtocol(
  requestJson: string,
  configJson?: string
): { error: ReclaimError; claimJson: string | null; claimLength: number; rawPointer: RawPointer | null } {
  if (!lib || !_reclaim_execute_protocol) {
    throw new Error('Library not loaded. Call loadLibrary() first.');
  }

  // Create output pointers
  const claimJsonPtr: [RawPointer | null] = [null];
  const claimLengthPtr = [0];

  const error = _reclaim_execute_protocol(
    requestJson,
    configJson || '',
    claimJsonPtr,
    claimLengthPtr
  ) as ReclaimError;

  const rawPointer = claimJsonPtr[0];
  const claimLength = claimLengthPtr[0] as number;

  // Decode the raw pointer to string if we have data
  let claimJson: string | null = null;
  if (rawPointer && claimLength > 0) {
    claimJson = koffi.decode(rawPointer, 'char', claimLength) as string;
  }

  return { error, claimJson, claimLength, rawPointer };
}

/**
 * Free a pointer allocated by the library
 * @param ptr - Raw pointer to free (from executeProtocol's rawPointer)
 */
export function freePointer(ptr: RawPointer | null): void {
  if (!lib || !_reclaim_free_string) {
    throw new Error('Library not loaded. Call loadLibrary() first.');
  }

  if (ptr !== null) {
    _reclaim_free_string(ptr);
  }
}

/**
 * Get human-readable error message for an error code
 * @param error - Error code
 * @returns Error message string
 */
export function getErrorMessage(error: ReclaimError): string {
  if (!lib || !_reclaim_get_error_message) {
    throw new Error('Library not loaded. Call loadLibrary() first.');
  }

  return _reclaim_get_error_message(error) as string;
}

/**
 * Get the library version
 * @returns Version string
 */
export function getVersion(): string {
  if (!lib || !_reclaim_get_version) {
    throw new Error('Library not loaded. Call loadLibrary() first.');
  }

  return _reclaim_get_version() as string;
}

/**
 * Initialize a ZK algorithm with proving key and R1CS
 * @param algorithmId - Algorithm ID (use AlgorithmID enum)
 * @param provingKey - Proving key bytes
 * @param r1cs - R1CS constraint system bytes
 * @returns true if initialization succeeded, false otherwise
 */
export function initAlgorithm(
  algorithmId: AlgorithmID,
  provingKey: Buffer,
  r1cs: Buffer
): boolean {
  if (!lib || !_init_algorithm) {
    throw new Error('Library not loaded. Call loadLibrary() first.');
  }

  // Create GoSlice structures
  const pkSlice = {
    data: provingKey,
    len: BigInt(provingKey.length),
    cap: BigInt(provingKey.length),
  };

  const r1csSlice = {
    data: r1cs,
    len: BigInt(r1cs.length),
    cap: BigInt(r1cs.length),
  };

  const result = _init_algorithm(algorithmId, pkSlice, r1csSlice) as number;
  return result !== 0;
}
