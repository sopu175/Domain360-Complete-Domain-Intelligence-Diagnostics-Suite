import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";
import { ThemeProvider } from "@/components/domain360/theme-provider";

const interSans = Inter({
  variable: "--font-sans",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Domain360 — Complete Domain Intelligence & Diagnostics",
  description:
    "Real-time DNS diagnostics, SSL/TLS certificate analysis, WHOIS/RDAP lookup, email security (SPF, DKIM, DMARC), DNS propagation, DNSSEC validation, HTTP security headers, subdomain discovery and domain health scoring — all in one tool.",
  keywords: [
    "DNS checker", "SSL checker", "WHOIS lookup", "RDAP", "DMARC", "SPF", "DKIM",
    "DNS propagation", "DNSSEC", "domain health score", "HTTP headers", "security headers",
    "subdomain finder", "IP lookup", "domain diagnostics",
  ],
  authors: [{ name: "Domain360" }],
  openGraph: {
    title: "Domain360 — Complete Domain Intelligence & Diagnostics",
    description:
      "Enter any domain and get a complete technical report: DNS, SSL, WHOIS, email security, HTTP headers, DNSSEC, subdomains and a transparent health score.",
    type: "website",
  },
  icons: {
    icon: [
      { url: '/icon.svg', type: 'image/svg+xml' },
      { url: '/favicon.ico' },
    ],
    apple: [{ url: '/apple-icon.png' }],
  },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#fafafa" },
    { media: "(prefers-color-scheme: dark)", color: "#09090b" },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${interSans.variable} ${jetbrainsMono.variable} font-sans antialiased bg-background text-foreground selection:bg-emerald-500/20 selection:text-emerald-800 dark:selection:bg-emerald-500/30 dark:selection:text-emerald-200`}
      >
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
          {children}
        </ThemeProvider>
        <Toaster />
      </body>
    </html>
  );
}
