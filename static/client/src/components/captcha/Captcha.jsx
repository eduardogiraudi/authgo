import { useEffect, useRef } from 'react';
import 'altcha';

const Captcha = ({ setRecaptchaValue, className = "" }) => {
  const altchaRef = useRef(null);

  useEffect(() => {
    const currentRef = altchaRef.current;

    const handleStateChange = (ev) => {
      if (ev.detail.state === 'verified') {
        setRecaptchaValue(ev.detail.payload);
      } else {
        setRecaptchaValue(null);
      }
    };

    if (currentRef) {
      if (typeof currentRef.configure === 'function') {
        currentRef.configure({
          hidelogo: true,
          auto: 'onload',
          hidefooter: true,
        });
      }

      currentRef.addEventListener('statechange', handleStateChange);
      return () => currentRef.removeEventListener('statechange', handleStateChange);
    }
  }, [setRecaptchaValue]);

  return (
    <div className={className}>
      <altcha-widget
        ref={altchaRef}
        challengeurl={window.location.origin+import.meta.env.VITE_ALTCHA_CHALLENGE_PATH}
        hidelogo="true"
        hidefooter="true"
        auto="onload"
        lang="auto" 
        style={{
          width: '100%',
          "--altcha-max-width": "100%",
          "--altcha-border-radius": "4px",
        }}
      ></altcha-widget>
    </div>
  );
};

export default Captcha;