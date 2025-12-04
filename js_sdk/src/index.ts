import * as bindings from './bindings';
import * as fs from 'fs';
import * as path from 'path';

export { ReclaimError, AlgorithmID } from './bindings';

// Types matching the Go structures

export interface Signature {
  attestor_address: string;
  claim_signature: string;
}

export interface ClaimData {
  identifier: string;
  owner: string;
  provider: string;
  parameters: string;
  context: string;
  timestamp_s: number;
  epoch: number;
  error?: string;
}

export interface ProtocolResult {
  claim: ClaimData;
  signatures: Signature[];
}

export interface ProviderRequest {
  name: string;
  secretParams?: Record<string, unknown>;
  context?: string;
  [key: string]: unknown;
}

export interface ReclaimConfig {
  teekUrl?: string;
  teetUrl?: string;
  attestorUrl?: string;
  timeout_ms?: number;
  [key: string]: unknown;
}

export interface CircuitConfig {
  algorithmId: bindings.AlgorithmID;
  pkFile: string;
  r1csFile: string;
  name: string;
}

// Default circuit configurations
const DEFAULT_CIRCUITS: CircuitConfig[] = [
  {
    algorithmId: bindings.AlgorithmID.CHACHA20_OPRF,
    pkFile: 'pk.chacha20_oprf',
    r1csFile: 'r1cs.chacha20_oprf',
    name: 'CHACHA20_OPRF',
  },
  {
    algorithmId: bindings.AlgorithmID.AES_128_OPRF,
    pkFile: 'pk.aes128_oprf',
    r1csFile: 'r1cs.aes128_oprf',
    name: 'AES_128_OPRF',
  },
  {
    algorithmId: bindings.AlgorithmID.AES_256_OPRF,
    pkFile: 'pk.aes256_oprf',
    r1csFile: 'r1cs.aes256_oprf',
    name: 'AES_256_OPRF',
  },
];

export class ReclaimProtocolError extends Error {
  public readonly code: bindings.ReclaimError;

  constructor(code: bindings.ReclaimError, message?: string) {
    super(message || bindings.getErrorMessage(code));
    this.code = code;
    this.name = 'ReclaimProtocolError';
  }
}

/**
 * Reclaim SDK class for executing the TEE protocol
 */
export class ReclaimSDK {
  private initialized = false;
  private libraryPath?: string;

  /**
   * Create a new ReclaimSDK instance
   * @param libraryPath - Optional path to libreclaim.so
   */
  constructor(libraryPath?: string) {
    this.libraryPath = libraryPath;
  }

  /**
   * Initialize the SDK by loading the native library
   */
  public init(): void {
    if (this.initialized) {
      return;
    }
    bindings.loadLibrary(this.libraryPath);
    this.initialized = true;
  }

  /**
   * Get the library version
   */
  public getVersion(): string {
    this.ensureInitialized();
    return bindings.getVersion();
  }

  /**
   * Initialize a single ZK algorithm with proving key and R1CS files
   * @param algorithmId - Algorithm ID
   * @param provingKey - Proving key buffer
   * @param r1cs - R1CS buffer
   * @returns true if successful
   */
  public initAlgorithm(
    algorithmId: bindings.AlgorithmID,
    provingKey: Buffer,
    r1cs: Buffer
  ): boolean {
    this.ensureInitialized();
    return bindings.initAlgorithm(algorithmId, provingKey, r1cs);
  }

  /**
   * Initialize ZK circuits from a directory containing circuit files
   * @param circuitsPath - Path to directory containing pk.* and r1cs.* files
   * @param circuits - Optional custom circuit configurations (defaults to all OPRF circuits)
   * @throws Error if circuit files are not found or initialization fails
   */
  public initializeZKCircuits(
    circuitsPath: string,
    circuits: CircuitConfig[] = DEFAULT_CIRCUITS
  ): void {
    this.ensureInitialized();

    if (!fs.existsSync(circuitsPath)) {
      throw new Error(`Circuits directory not found: ${circuitsPath}`);
    }

    for (const circuit of circuits) {
      const pkPath = path.join(circuitsPath, circuit.pkFile);
      const r1csPath = path.join(circuitsPath, circuit.r1csFile);

      if (!fs.existsSync(pkPath)) {
        throw new Error(`Proving key not found: ${pkPath}`);
      }
      if (!fs.existsSync(r1csPath)) {
        throw new Error(`R1CS file not found: ${r1csPath}`);
      }

      const pkData = fs.readFileSync(pkPath);
      const r1csData = fs.readFileSync(r1csPath);

      const success = bindings.initAlgorithm(circuit.algorithmId, pkData, r1csData);
      if (!success) {
        throw new Error(`Failed to initialize ${circuit.name} circuit`);
      }
    }
  }

  /**
   * Execute the Reclaim protocol
   * @param request - Provider request data
   * @param config - Optional configuration
   * @returns Protocol result with claim and signatures
   * @throws ReclaimProtocolError on failure
   */
  public executeProtocol(
    request: ProviderRequest,
    config?: ReclaimConfig
  ): ProtocolResult {
    this.ensureInitialized();

    const requestJson = JSON.stringify(request);
    const configJson = config ? JSON.stringify(config) : undefined;

    const { error, claimJson, rawPointer } = bindings.executeProtocol(
      requestJson,
      configJson
    );

    if (error !== bindings.ReclaimError.SUCCESS) {
      // Free the pointer even on error if it was allocated
      if (rawPointer) {
        bindings.freePointer(rawPointer);
      }
      throw new ReclaimProtocolError(error);
    }

    if (!claimJson) {
      if (rawPointer) {
        bindings.freePointer(rawPointer);
      }
      throw new ReclaimProtocolError(
        bindings.ReclaimError.MEMORY,
        'No claim data returned'
      );
    }

    try {
        return JSON.parse(claimJson) as ProtocolResult;
    } finally {
      // Free the allocated pointer
      if (rawPointer) {
        bindings.freePointer(rawPointer);
      }
    }
  }

  /**
   * Execute the protocol asynchronously (wraps sync call in a Promise)
   */
  public async executeProtocolAsync(
    request: ProviderRequest,
    config?: ReclaimConfig
  ): Promise<ProtocolResult> {
    return new Promise((resolve, reject) => {
      setImmediate(() => {
        try {
          const result = this.executeProtocol(request, config);
          resolve(result);
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      this.init();
    }
  }
}

// Convenience function for one-off usage
export function createReclaimSDK(libraryPath?: string): ReclaimSDK {
  const sdk = new ReclaimSDK(libraryPath);
  sdk.init();
  return sdk;
}

// Re-export bindings for advanced usage
export { loadLibrary, getErrorMessage, getVersion, initAlgorithm, freePointer } from './bindings';

// Export default circuits for custom initialization
export { DEFAULT_CIRCUITS };
