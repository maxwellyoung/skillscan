import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        accent: "hsl(355, 78%, 58%)", // Design system accent color
        background: "#000000", // True black
        foreground: "hsl(0, 0%, 90%)", // Design system foreground
        muted: "hsl(0, 0%, 25%)",
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'monospace'],
        sans: ['Inter', 'General Sans', 'system-ui', 'sans-serif'],
        serif: ['Charter', 'Sentient', 'Georgia', 'serif'],
      },
      letterSpacing: {
        'wider': '0.05em',
        'widest': '0.1em',
      },
      animation: {
        'spring-in': 'spring-in 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275)',
        'stagger': 'stagger 0.6s ease-out forwards',
        'count-up': 'count-up 1.5s ease-out forwards',
      },
      keyframes: {
        'spring-in': {
          '0%': { 
            transform: 'scale(0.8) translateY(20px)',
            opacity: '0'
          },
          '100%': { 
            transform: 'scale(1) translateY(0px)',
            opacity: '1'
          },
        },
        'stagger': {
          '0%': { 
            transform: 'translateX(-20px)',
            opacity: '0'
          },
          '100%': { 
            transform: 'translateX(0px)',
            opacity: '1'
          },
        },
        'count-up': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
export default config;
