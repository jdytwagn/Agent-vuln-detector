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
        "on-primary-container": "#1E4E8C",
        "on-tertiary-container": "#35476b",
        "error-container": "#fa746f",
        tertiary: "#4d5f84",
        "secondary-dim": "#41565f",
        "secondary-fixed": "#cfe6f1",
        "on-background": "#122033",
        "on-error-container": "#6e0a12",
        "primary-container": "#E8F2FF",
        "inverse-surface": "#122033",
        "surface-container": "#F7F9FC",
        "on-tertiary": "#1B2836",
        background: "#F4F7FB",
        "on-secondary-container": "#40555e",
        "secondary-container": "#cfe6f1",
        "surface-container-high": "#EEF2F7",
        "surface-dim": "#E6EDF5",
        "surface-bright": "#FFFFFF",
        "surface-variant": "#F6F8FB",
        surface: "#FFFFFF",
        outline: "#8AA0B5",
        "on-secondary": "#f2faff",
        "surface-container-lowest": "#ffffff",
        "on-surface-variant": "#5E7084",
        "surface-container-low": "#F3F6FA",
        "on-primary": "#FFFFFF",
        "surface-tint": "#006882",
        error: "#C43832",
        "outline-variant": "#D5DEE8",
        "on-surface": "#1B2836",
        "inverse-on-surface": "#969ea8",
        "inverse-primary": "#93dffe",
        secondary: "#3D6F99",
        primary: "#4C8DFF",
        "primary-dim": "#2F6FE0",
        "status-amber": "#9A6200",
        "status-green": "#0F7A45",
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
