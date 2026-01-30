import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SkillScan - Security Scanner for Claude Code Skills",
  description: "Scan Claude Code skills and MCP servers for security risks before they access your system. Fast, free security analysis.",
  keywords: "claude code, mcp, security scanner, static analysis, skill scanner",
  authors: [{ name: "SkillScan Team" }],
  themeColor: "#00FF88",
  viewport: "width=device-width, initial-scale=1",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <link rel="icon" href="/favicon.ico" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
