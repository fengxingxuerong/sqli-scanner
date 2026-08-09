/** @type {import('tailwindcss').Config} */
// Tailwind 配置：仅负责布局与主题微调（MUI 负责组件）
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        risk: {
          critical: '#c62828',
          high: '#ef6c00',
          medium: '#f9a825',
          low: '#9e9e9e',
        },
      },
    },
  },
  plugins: [],
};
