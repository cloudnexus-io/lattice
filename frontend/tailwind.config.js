/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#0a0a0c',
          card: '#121216',
          neon: '#00ff9d',
          accent: '#7000ff',
          text: '#e2e2e7'
        }
      }
    },
  },
  plugins: [],
}
