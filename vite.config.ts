import { defineConfig, type Plugin } from "vite";

/**
 * Makes LZMA-JS importable as an ES module.
 *
 * The package ships a plain script that ends in
 * `this.LZMA = this.LZMA_WORKER = <decoder>;`. Node's CJS loader turns that
 * into an export because top-level `this` is `module.exports` there; an ES
 * module bundler sees a file with no exports at all, and `this` is `undefined`.
 * Rewriting that one line is enough, and keeps the dependency on npm where it
 * gets version pinning, integrity hashes and upstream fixes.
 *
 * If upstream ever changes that line the build fails loudly here rather than
 * emitting a module whose decoder is missing.
 */
function lzmaEsm(): Plugin {
    const TAIL = /this\.LZMA\s*=\s*this\.LZMA_WORKER\s*=\s*(\w+)\s*;?/;

    return {
        name: "lzma-esm",
        enforce: "pre",
        transform(code, id) {
            if (!/[\/]lzma[\/]src[\/]lzma-d(-min)?\.js$/.test(id)) {
                return null;
            }
            if (!TAIL.test(code)) {
                throw new Error(
                    `${id} no longer ends with the expected global assignment, so it ` +
                        "cannot be converted to an ES module. Check what upstream changed " +
                        "before touching this plugin — the LZMA decoder is what extracts " +
                        "the bootloader image the unlock payload is built from.",
                );
            }
            return {
                // Minified builds bind the decoder to a mangled name, so capture it.
                code: code.replace(TAIL, "export default { LZMA: $1, LZMA_WORKER: $1 };"),
                map: null,
            };
        },
    };
}

export default defineConfig({
    plugins: [lzmaEsm()],
    // WebUSB needs a secure context; localhost qualifies.
    server: { port: 5173, host: "localhost" },
    build: { target: "es2022" },
});
