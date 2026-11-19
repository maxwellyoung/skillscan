import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import { Newsreader } from "next/font/google";
import { SITE_URL } from "@/lib/site";
import "./globals.css";

const sans = localFont({ src: "./fonts/GeistVF.woff", variable: "--font-sans", weight: "100 900" });
const mono = localFont({ src: "./fonts/GeistMonoVF.woff", variable: "--font-mono", weight: "100 900" });
const serif = Newsreader({ subsets: ["latin"], variable: "--font-serif", weight: ["300", "400"], style: ["normal"] });

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#000000",
};

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: "SkillScan – Security Scanner for AI Skills, npm & VS Code",
  description:
    "Static checks for agent skills, MCP servers, npm packages, VS Code extensions and GitHub Actions. Review findings in the browser, npm CLI or CI.",
  alternates: { canonical: '/' },
  keywords:
    "claude code, mcp, npm security, vscode extension security, security scanner, static analysis, skill scanner, ai security, vulnerability scanner, github security, code analysis, supply chain security",
  authors: [{ name: "ninetynine.digital", url: "https://ninetynine.digital" }],
  openGraph: {
    title: "SkillScan – Security Scanner for AI Skills, npm & VS Code",
    description:
      "Free, instant security analysis for AI skills, npm packages, VS Code extensions, GitHub Actions, and MCP servers. 29 deterministic checks. Know what you're installing.",
    url: SITE_URL,
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
      <body className={`${sans.variable} ${mono.variable} ${serif.variable} font-sans antialiased`}>
        {children}
      </body>
    </html>
  );
}
