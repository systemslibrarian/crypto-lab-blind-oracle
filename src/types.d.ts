declare module '*.css' {
  const value: string
  export default value
}

declare module 'tfhe' {
  export default function initTfhe(): Promise<void>

  export class TfheConfigBuilder {
    static default(): TfheConfigBuilder
    build(): TfheConfig
  }

  export class TfheConfig {}

  export class TfheClientKey {
    static generate(config: TfheConfig): TfheClientKey
  }

  export class TfheCompressedServerKey {
    static new(clientKey: TfheClientKey): TfheCompressedServerKey
    safe_serialize(serializedSizeLimit: bigint): Uint8Array
  }

  export class FheUint8 {
    static encrypt_with_client_key(value: number, clientKey: TfheClientKey): FheUint8
    static safe_deserialize(bytes: Uint8Array, serializedSizeLimit: bigint): FheUint8
    safe_serialize(serializedSizeLimit: bigint): Uint8Array
    decrypt(clientKey: TfheClientKey): number
  }
}
