import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Space_Grotesk, Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
  weight: ["500", "600", "700"],
});

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  weight: ["400", "500", "600"],
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "PyPortScan-Lab | Python TCP Network Port Scanner & Security Telemetry",
  description:
    "Command-line and web-assisted TCP port scanning utility in Python using the socket library to identify open ports, grab service banners, and export structured TXT/CSV security reports for authorized local test systems and VirtualBox lab environments.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="en"
      className={`${spaceGrotesk.variable} ${inter.variable} ${jetbrainsMono.variable} dark`}
    >
      <body className="min-h-screen bg-[#090D16] text-[#F8FAFC] font-sans antialiased selection:bg-[#10B981]/30 selection:text-[#10B981]">
        {children}
      </body>
    </html>
  );
}
