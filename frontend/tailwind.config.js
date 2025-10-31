/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          green: '#00ff88',
          blue: '#0066ff',
          red: '#ff3366',
          yellow: '#ffff00',
          bg: '#0a0a0a',
          surface: '#1a1a1a',
          border: '#333333',
        },
      },
      fontFamily: {
        'cyber': ['Courier New', 'monospace'],
      },
      animation: {
        'pulse-cyber': 'pulse-cyber 2s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite',
        'matrix-rain': 'matrix-rain 3s linear infinite',
        'scan-pulse': 'scan-pulse 2s ease-in-out infinite',
      },
      keyframes: {
        'pulse-cyber': {
          '0%, 100%': {
            opacity: '1',
          },
          '50%': {
            opacity: '0.5',
          },
        },
        'glow': {
          '0%, 100%': {
            textShadow: '0 0 5px #00ff88',
          },
          '50%': {
            textShadow: '0 0 20px #00ff88, 0 0 30px #00ff88',
          },
        },
        'matrix-rain': {
          '0%': {
            transform: 'translateY(-100vh)',
          },
          '100%': {
            transform: 'translateY(100vh)',
          },
        },
        'scan-pulse': {
          '0%': {
            boxShadow: '0 0 0 0 rgba(16, 185, 129, 0.7)',
          },
          '70%': {
            boxShadow: '0 0 0 10px rgba(16, 185, 129, 0)',
          },
          '100%': {
            boxShadow: '0 0 0 0 rgba(16, 185, 129, 0)',
          },
        },
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(0, 255, 136, 0.3)',
        'cyber-lg': '0 0 30px rgba(0, 255, 136, 0.5)',
        'cyber-xl': '0 0 40px rgba(0, 255, 136, 0.7)',
        'scan': '0 0 30px rgba(16, 185, 129, 0.5)',
      },
      backgroundImage: {
        'cyber-gradient': 'linear-gradient(45deg, #00ff88, #0066ff)',
        'danger-gradient': 'linear-gradient(45deg, #ff3366, #ff6666)',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),
  ],
}