import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Technocore Helper",
  description: "A simple browser-based helper for the Technocore DID workflow.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
