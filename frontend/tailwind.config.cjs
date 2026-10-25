const forms = require("@tailwindcss/forms");

const sans = [
  "DM Sans",
  "WenQuanYi Micro Hei",
  "PingFang SC",
  "Microsoft YaHei",
  "Noto Sans SC",
  "sans-serif"
];

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        "on-tertiary-fixed-variant": "#3e5175",
        "on-error": "#fff7f6",
        "on-primary-container": "#BFFFF4",
        "on-tertiary-container": "#35476b",
        "error-container": "#fa746f",
        tertiary: "#4d5f84",
        "secondary-dim": "#41565f",
        "secondary-fixed": "#cfe6f1",
        "on-background": "#F3FFFC",
        "on-error-container": "#6e0a12",
        "primary-container": "#D9FFF6",
        "inverse-surface": "#04050A",
        "surface-container": "#121A20",
        "on-tertiary": "#E8F7F4",
        background: "#04050A",
        "on-secondary-container": "#40555e",
        "secondary-container": "#cfe6f1",
        "surface-container-high": "#1A262C",
        "surface-dim": "#070B10",
        "surface-bright": "#1C2A30",
        "surface-variant": "#10181E",
        surface: "#0C141A",
        outline: "#3E5652",
        "on-secondary": "#f2faff",
        "surface-container-lowest": "#ffffff",
        "on-surface-variant": "#9BB4B0",
        "surface-container-low": "#0A1216",
        "on-primary": "#041410",
        "surface-tint": "#006882",
        error: "#FF8B84",
        "outline-variant": "#2C403C",
        "on-surface": "#E8F7F4",
        "inverse-on-surface": "#969ea8",
        "inverse-primary": "#93dffe",
        secondary: "#9AD7FF",
        primary: "#2EE6C8",
        "primary-dim": "#14C4B0",
        "status-amber": "#F5C15A",
        "status-green": "#8CFF9A",
        "code-bg": "#070B10",
        "code-text": "#D7FFF4"
      },
      borderRadius: {
        DEFAULT: "0.25rem",
        lg: "0.5rem",
        xl: "0.75rem",
        full: "9999px"
      },
      fontFamily: {
        headline: sans,
        display: sans,
        body: sans,
        label: sans,
        sans
      },
      boxShadow: {
        card: "0 1px 3px rgba(16, 24, 32, 0.05), 0 4px 12px rgba(16, 24, 32, 0.04)"
      }
    }
  },
  plugins: [forms]
};
