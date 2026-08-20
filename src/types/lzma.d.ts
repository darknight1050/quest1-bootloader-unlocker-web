declare module "*/vendor/lzma-d.js" {
    interface LzmaDecompressor {
        decompress(
            data: number[] | Uint8Array,
            callback: (result: number[] | string, error: Error | null) => void,
        ): void;
    }
    const module: { LZMA: LzmaDecompressor; LZMA_WORKER: LzmaDecompressor };
    export default module;
}
