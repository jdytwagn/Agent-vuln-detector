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
        "on-primary-container": "#005065",
        "on-tertiary-container": "#35476b",
        "error-container": "#fa746f",
        tertiary: "#4d5f84",
        "secondary-dim": "#41565f",
        "secondary-fixed": "#cfe6f1",
        "on-background": "#233444",
        "on-error-container": "#6e0a12",
        "primary-container": "#93dffe",
        "inverse-surface": "#101820",
        "surface-container": "#e3efff",
        "on-tertiary": "#f9f8ff",
        background: "#D7E0EA",
        "on-secondary-container": "#40555e",
        "secondary-container": "#cfe6f1",
        "surface-container-high": "#dbeafc",
        "surface-dim": "#cadcf1",
        "surface-bright": "#f7f9ff",
        "surface-variant": "#EEF3F8",
        surface: "#ffffff",
        outline: "#6b7c90",
        "on-secondary": "#f2faff",
        "surface-container-lowest": "#ffffff",
        "on-surface-variant": "#506173",
        "surface-container-low": "#edf4ff",
        "on-primary": "#f2faff",
        "surface-tint": "#006882",
        error: "#a83836",
        "outline-variant": "#a2b4c8",
        "on-surface": "#233444",
        "inverse-on-surface": "#969ea8",
        "inverse-primary": "#93dffe",
        secondary: "#4d626c",
        primary: "#0F6F8A",
        "primary-dim": "#005b72",
        "status-amber": "#B4690E",
        "status-green": "#1B7F5F",
        "code-bg": "#101820",
        "code-text": "#D7E4F2"
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
