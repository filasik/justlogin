#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ASSETS="$ROOT/docs/assets"
GALLERY="$ROOT/docs/gallery"

MAC_RENDERER=""
MAC_RENDERER_SRC=""
cleanup_mac_renderer() {
  rm -f "${MAC_RENDERER:-}" "${MAC_RENDERER_SRC:-}"
}
trap cleanup_mac_renderer EXIT

ensure_mac_renderer() {
  if [[ -n "$MAC_RENDERER" ]]; then
    return 0
  fi
  MAC_RENDERER_SRC="$(mktemp /tmp/justlogin-render-XXXXXX.swift)"
  MAC_RENDERER="${MAC_RENDERER_SRC%.swift}.bin"

  cat > "$MAC_RENDERER_SRC" << 'SWIFT'
import AppKit
import Foundation
import WebKit

final class Renderer: NSObject, WKNavigationDelegate {
    let app = NSApplication.shared
    let width: Int
    let height: Int
    let outputURL: URL
    let webView: WKWebView
    let window: NSWindow

    init(width: Int, height: Int, output: String) {
        self.width = width
        self.height = height
        self.outputURL = URL(fileURLWithPath: output)
        let frame = NSRect(x: 0, y: 0, width: width, height: height)
        let cfg = WKWebViewConfiguration()
        self.webView = WKWebView(frame: frame, configuration: cfg)
        self.webView.setValue(false, forKey: "drawsBackground")
        self.window = NSWindow(
            contentRect: frame,
            styleMask: [.borderless],
            backing: .buffered,
            defer: false
        )
        super.init()
        self.window.isOpaque = false
        self.window.backgroundColor = .clear
        self.window.contentView = self.webView
        self.webView.navigationDelegate = self
    }

    func load(file: String) {
        let url = URL(fileURLWithPath: file)
        if file.hasSuffix(".svg"), let svg = try? String(contentsOf: url, encoding: .utf8) {
            let html = """
            <!doctype html>
            <html>
            <head><meta charset="utf-8"><style>
              * { margin: 0; padding: 0; }
              html, body { width: \(width)px; height: \(height)px; background: transparent; overflow: hidden; }
              svg { display: block; width: \(width)px; height: \(height)px; }
            </style></head>
            <body>\(svg)</body>
            </html>
            """
            webView.loadHTMLString(html, baseURL: url.deletingLastPathComponent())
        } else {
            webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
            let snapCfg = WKSnapshotConfiguration()
            snapCfg.rect = NSRect(x: 0, y: 0, width: self.width, height: self.height)
            snapCfg.snapshotWidth = NSNumber(value: self.width)
            webView.takeSnapshot(with: snapCfg) { image, error in
                if let error = error {
                    fputs("Snapshot error: \(error)\n", stderr)
                    exit(1)
                }
                guard let image = image,
                      let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
                    fputs("Failed to obtain CGImage\n", stderr)
                    exit(1)
                }
                guard let ctx = CGContext(
                    data: nil,
                    width: self.width,
                    height: self.height,
                    bitsPerComponent: 8,
                    bytesPerRow: 0,
                    space: CGColorSpaceCreateDeviceRGB(),
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
                ) else {
                    fputs("Failed to allocate CGContext\n", stderr)
                    exit(1)
                }
                ctx.clear(CGRect(x: 0, y: 0, width: self.width, height: self.height))
                ctx.interpolationQuality = .high
                ctx.draw(cgImage, in: CGRect(x: 0, y: 0, width: self.width, height: self.height))
                guard let outCg = ctx.makeImage() else {
                    fputs("Failed to make CGImage\n", stderr)
                    exit(1)
                }
                let rep = NSBitmapImageRep(cgImage: outCg)
                guard let pngData = rep.representation(using: .png, properties: [:]) else {
                    fputs("Failed to encode PNG\n", stderr)
                    exit(1)
                }
                do {
                    try pngData.write(to: self.outputURL)
                    exit(0)
                } catch {
                    fputs("Write error: \(error)\n", stderr)
                    exit(1)
                }
            }
        }
    }
}

guard CommandLine.arguments.count == 5,
      let w = Int(CommandLine.arguments[3]),
      let h = Int(CommandLine.arguments[4]) else {
    fputs("Usage: swift renderer.swift <input> <output> <width> <height>\n", stderr)
    exit(2)
}

let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
let renderer = Renderer(width: w, height: h, output: CommandLine.arguments[2])
renderer.load(file: CommandLine.arguments[1])
app.run()
SWIFT

  swiftc -O "$MAC_RENDERER_SRC" -o "$MAC_RENDERER"
}

render_mac_webkit() {
  ensure_mac_renderer
  "$MAC_RENDERER" "$@"
}

render_svg() {
  local svg="$1" png="$2" w="$3" h="$4"
  if command -v rsvg-convert >/dev/null 2>&1; then
    rsvg-convert -w "$w" -h "$h" "$svg" -o "$png"
  elif command -v resvg >/dev/null 2>&1; then
    resvg -w "$w" -h "$h" "$svg" "$png"
  elif command -v swift >/dev/null 2>&1 && [[ "$(uname -s)" == "Darwin" ]]; then
    render_mac_webkit "$svg" "$png" "$w" "$h"
  else
    echo "No SVG renderer found (need rsvg-convert, resvg, or macOS swift/WebKit); skipping $png"
    return 0
  fi
  echo "Rendered $png (${w}x${h})"
}

render_html() {
  local html="$1" png="$2" w="$3" h="$4"
  if command -v google-chrome >/dev/null 2>&1; then
    google-chrome --headless --disable-gpu --window-size="${w},${h}" --screenshot="$png" "file://$html" >/dev/null 2>&1
  elif command -v chromium >/dev/null 2>&1; then
    chromium --headless --disable-gpu --window-size="${w},${h}" --screenshot="$png" "file://$html" >/dev/null 2>&1
  elif command -v swift >/dev/null 2>&1 && [[ "$(uname -s)" == "Darwin" ]]; then
    render_mac_webkit "$html" "$png" "$w" "$h"
  else
    echo "No HTML renderer found (need chromium/google-chrome or macOS swift/WebKit); skipping $png"
    return 0
  fi
  echo "Rendered $png (${w}x${h})"
}

render_svg "$ASSETS/icon.svg" "$ASSETS/icon.png" 512 512
render_svg "$ASSETS/banner.svg" "$ASSETS/banner.png" 1200 300

for html in "$GALLERY"/*.html; do
  [[ -e "$html" ]] || continue
  render_html "$html" "${html%.html}.png" 1280 720
done

# Web editor: render the real docs/editor/index.html with demo data (light theme, 1280x720).
EDITOR_TMP="$(mktemp -d /tmp/justlogin-editor-XXXXXX)"
sed -e 's#<head>#<head><script>window.JL_DEMO=true;document.documentElement.dataset.theme="light";</script>#' \
    -e 's|</body>|<script>(() => { const r = document.querySelectorAll("#rows tr"); r[2].querySelector("button.cracked").click(); r[0].querySelector(".switch input").click(); })();</script></body>|' \
  "$ROOT/docs/editor/index.html" > "$EDITOR_TMP/index.html"
render_html "$EDITOR_TMP/index.html" "$GALLERY/web-editor.png" 1280 720
rm -rf "$EDITOR_TMP"
