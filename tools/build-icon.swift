// Render the existing clipboard/arrows mark into a native macOS icon family.
import AppKit
let root = URL(fileURLWithPath: CommandLine.arguments[1])
try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let size = base * scale
        let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size,
            bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
            colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        let context = NSGraphicsContext.current!.cgContext
        context.scaleBy(x: CGFloat(size) / 32, y: CGFloat(size) / 32)
        NSColor(srgbRed: 0.10, green: 0.43, blue: 0.94, alpha: 1).setFill()
        NSBezierPath(roundedRect: NSRect(x: 1, y: 1, width: 30, height: 30), xRadius: 6, yRadius: 6).fill()
        context.translateBy(x: 4, y: 28)
        context.scaleBy(x: 1, y: -1)
        NSColor.white.setStroke()
        for points: [(CGFloat, CGFloat)] in [
            [(6,4),(4,4),(4,21),(20,21),(20,4),(18,4)],
            [(8,3),(16,3),(16,7),(8,7),(8,3)],
            [(7,11),(17,11),(14,8)], [(17,16),(7,16),(10,19)]
        ] {
            let path = NSBezierPath()
            path.lineWidth = 1.7
            path.lineCapStyle = .round
            path.lineJoinStyle = .round
            path.move(to: NSPoint(x: points[0].0, y: points[0].1))
            for point in points.dropFirst() { path.line(to: NSPoint(x: point.0, y: point.1)) }
            path.stroke()
        }
        NSGraphicsContext.restoreGraphicsState()
        let suffix = scale == 2 ? "@2x" : ""
        try bitmap.representation(using: .png, properties: [:])!.write(to:
            root.appendingPathComponent("icon_\(base)x\(base)\(suffix).png"))
    }
}
