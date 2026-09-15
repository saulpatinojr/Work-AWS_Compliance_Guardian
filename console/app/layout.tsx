import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Continuous Compliance Guardian",
  description: "Sandbox compliance findings and Cedar-governed remediation evidence",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
