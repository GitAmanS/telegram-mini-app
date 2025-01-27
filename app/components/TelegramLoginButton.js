'use client';

import { useEffect } from 'react';

export const TelegramLoginButton = () => {
  useEffect(() => {
    const script = document.createElement('script');
    script.src = 'https://telegram.org/js/telegram-widget.js?7';
    script.async = true;
    script.setAttribute('data-telegram-login', 'YOUR_BOT_USERNAME');
    script.setAttribute('data-size', 'large');
    script.setAttribute('data-auth-url', '/api/auth/telegram');
    document.getElementById('telegram-login').appendChild(script);
  }, []);

  return <div id="telegram-login"></div>;
};
