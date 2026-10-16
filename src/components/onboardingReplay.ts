// onboardingReplay.ts —— 「重新查看新手引导」跨组件触发（D86）
// 背景：OnboardingTour 的欢迎文案承诺「随时可回看」，但 D85 只做了自动弹出，
// 没有回看入口——文案与功能不符是真缺口，本 hook 补上。
// 通道：window CustomEvent（'sqli:onboarding:replay'）。帮助中心按钮 dispatch，
// OnboardingTour 监听。选事件而非提升 state：OnboardingTour 挂 App 层、
// 触发点在 TopBar 内的 HelpCenter，提升 state 要穿三层且搅乱 App 的引擎门禁。

import { useEffect } from 'react';

// 事件名**不导出**：dispatch 与监听都在本文件内成对提供（replayOnboarding /
// useOnboardingReplay），跨文件引用为零——导出即死代码（deadcode 守卫会抓）。
const ONBOARDING_REPLAY_EVENT = 'sqli:onboarding:replay';

/** 监听回看事件；handler 由调用方 useCallback 稳定化（effect 依赖它）。
 *  effect 无条件注册（Rules of Hooks），window 判空放在 effect 内部。 */
export function useOnboardingReplay(onReplay: () => void) {
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const handler = () => onReplay();
    window.addEventListener(ONBOARDING_REPLAY_EVENT, handler);
    return () => window.removeEventListener(ONBOARDING_REPLAY_EVENT, handler);
  }, [onReplay]);
}

/** 帮助中心「重新查看新手引导」按钮的 dispatch（与 hook 同文件，事件名不漂移） */
export function replayOnboarding() {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(ONBOARDING_REPLAY_EVENT));
  }
}
