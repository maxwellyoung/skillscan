import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SkillScan - Security Scanner for AI Skills & Code",
  description: "Scan Claude Code skills, MCP servers, and GitHub repositories for security vulnerabilities before they access your system. Fast, comprehensive security analysis with detailed reporting.",
  keywords: "claude code, mcp, security scanner, static analysis, skill scanner, ai security, vulnerability scanner, github security, code analysis",
  authors: [{ name: "SkillScan Team" }, { name: "ninetynine.digital" }],
  themeColor: "hsl(355, 78%, 58%)",
  viewport: "width=device-width, initial-scale=1",
  openGraph: {
    title: "SkillScan - Security Scanner for AI Skills",
    description: "Comprehensive security analysis for Claude Code skills and repositories. Know what you're installing before it accesses your system.",
    url: "https://skillscan-rouge.vercel.app",
    siteName: "SkillScan",
    type: "website",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "SkillScan - Security Scanner for AI Skills",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "SkillScan - Security Scanner for AI Skills",
    description: "Scan skills for security vulnerabilities before they access your system.",
    images: ["/og-image.png"],
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
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
      </head>
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
