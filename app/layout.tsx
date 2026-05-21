import type { Metadata, Viewport } from "next";
import "./globals.css";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#000000",
};

export const metadata: Metadata = {
  metadataBase: new URL("https://skillscan.dev"),
  title: "SkillScan – Security Scanner for AI Skills, npm & VS Code",
  description:
    "Free, instant security scanning for AI skills, MCP servers, npm packages, VS Code extensions, GitHub Actions, and GitHub repos. 29 deterministic checks. Know what you're installing before it accesses your system.",
  keywords:
    "claude code, mcp, npm security, vscode extension security, security scanner, static analysis, skill scanner, ai security, vulnerability scanner, github security, code analysis, supply chain security",
  authors: [{ name: "ninetynine.digital", url: "https://ninetynine.digital" }],
  openGraph: {
    title: "SkillScan – Security Scanner for AI Skills, npm & VS Code",
    description:
      "Free, instant security analysis for AI skills, npm packages, VS Code extensions, GitHub Actions, and MCP servers. 29 deterministic checks. Know what you're installing.",
    url: "https://skillscan.dev",
    siteName: "SkillScan",
    type: "website",
    images: [
      {
        url: "/og-image",
        width: 1200,
        height: 630,
        alt: "SkillScan – Security Scanner for AI Skills, npm & VS Code",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "SkillScan – Security Scanner for AI Skills, npm & VS Code",
    description:
      "Scan AI skills, npm packages, VS Code extensions, and CI workflows before they access your system. Free & instant.",
    images: ["/og-image"],
  },
  robots: {
    index: true,
    follow: true,
  },
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
        <link
          rel="preconnect"
          href="https://fonts.gstatic.com"
          crossOrigin="anonymous"
        />
      </head>
      <body className="antialiased">{children}</body>
    </html>
  );
}
