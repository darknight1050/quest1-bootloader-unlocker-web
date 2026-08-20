/**
 * LZMA-JS ships no types, and this is a deep import into the package, so the
 * shape is declared here.
 *
 * Required for `tsc --noEmit` to pass: `strict` implies `noImplicitAny`, and an
 * untyped import is an error rather than an implicit `any`. `vite build` alone
 * would not care, but `npm run build` typechecks first.
 *
 * `vite.config.ts` rewrites this file's trailing global assignment into a
 * default export, so the shape below describes the module after that
 * transform, not the bytes on disk.
 */
declare module "lzma/src/lzma-d-min.js" {
    export interface LzmaDecompressor {
        /**
         * Decompresses an LZMA-alone stream.
         *
         * Hands back signed bytes as a plain array, or a string when the
         * result decodes as text; callers want the former.
         */
        decompress(
            data: number[] | Uint8Array,
            callback: (result: number[] | string, error: Error | null) => void,
        ): void;
    }

    const lzma: {
        readonly LZMA: LzmaDecompressor;
        readonly LZMA_WORKER: LzmaDecompressor;
    };
    export default lzma;
}
