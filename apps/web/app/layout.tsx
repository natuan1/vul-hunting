import type { Metadata } from "next";
import localFont from "next/font/local";
import Sidebar from "../components/Sidebar";
import "./globals.css";

// Font self-host (latin variable woff2 trong apps/web/fonts) — build trong
// docker không cần gọi ra mạng như next/font/google
const sans = localFont({
  src: "../fonts/SpaceGrotesk-latin.woff2",
  weight: "300 700",
  variable: "--font-sans",
  display: "swap",
});

const mono = localFont({
  src: "../fonts/JetBrainsMono-latin.woff2",
  weight: "100 800",
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "vul-hunting — bug bounty ops",
  description:
    "Trạm điều hành bug bounty cá nhân: thu thập Program, recon tự động, xác minh lỗ hổng bằng Hermes Agent.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="vi" className={`${sans.variable} ${mono.variable}`}>
      <body>
        <div className="shell">
          <Sidebar />
          <div className="main">{children}</div>
        </div>
      </body>
    </html>
  );
}
