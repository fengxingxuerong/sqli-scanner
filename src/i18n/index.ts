import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import zh from './zh.json';
import en from './en.json';

const savedLang = typeof window !== 'undefined' ? localStorage.getItem('sqli_lang') : null;

// 同步初始化：i18next v26 的 init 返回 Promise，但 i18n 实例在调用后立即可用
// 测试环境通过 waitForInitialization 确保已加载完成后再断言
i18n.use(initReactI18next).init({
  resources: {
    zh: { translation: zh },
    en: { translation: en },
  },
  lng: savedLang || 'zh',
  fallbackLng: 'zh',
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;