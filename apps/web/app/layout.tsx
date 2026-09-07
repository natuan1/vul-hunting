import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "vul-hunting",
  description: "Bug bounty hunting assistant",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="vi">
      <body>
        <header className="topnav">
          <a href="/" className="brand">vul-hunting</a>
          <nav>
            <a href="/">Trạng thái</a>
            <a href="/programs">Programs</a>
            <a href="/runs">Runs</a>
            <a href="/findings">Findings</a>
            <a href="/audit">Audit</a>
          </nav>
        </header>
        {children}
      </body>
    </html>
  );
}
