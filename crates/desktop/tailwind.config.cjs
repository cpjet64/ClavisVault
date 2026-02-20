/** @type {import("tailwindcss").Config} */
module.exports = {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: "rgb(var(--surface) / <alpha-value>)",
        panel: "rgb(var(--panel) / <alpha-value>)",
        accent: "rgb(var(--accent) / <alpha-value>)",
        text: "rgb(var(--text) / <alpha-value>)"
      },
      boxShadow: {
        glass: "0 20px 40px rgba(0,0,0,0.35)",
        soft: "0 10px 30px rgba(0,0,0,0.2)"
      },
      backdropBlur: {
        glass: "20px"
      }
    }
  },
  plugins: []
};
