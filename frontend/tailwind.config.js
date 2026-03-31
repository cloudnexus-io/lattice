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
          dark: 'var(--color-dark)',
          card: 'var(--color-card)',
          neon: 'var(--color-neon)',
          accent: 'var(--color-accent)',
          text: 'var(--color-text)',
        },
        theme: {
          DEFAULT: {
            dark: 'var(--color-dark)',
            card: 'var(--color-card)',
            neon: 'var(--color-neon)',
            accent: 'var(--color-accent)',
            text: 'var(--color-text)',
          },
          dark: 'var(--color-dark)',
          card: 'var(--color-card)',
          neon: 'var(--color-neon)',
          accent: 'var(--color-accent)',
          text: 'var(--color-text)',
        }
      }
    },
  },
  plugins: [],
}