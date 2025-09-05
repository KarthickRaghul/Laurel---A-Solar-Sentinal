import { useEffect } from 'react';
import ScrollReveal from 'scrollreveal';

export const useScrollReveal = () => {
  useEffect(() => {
    // Initialize ScrollReveal
    const sr = ScrollReveal({
      origin: 'bottom',
      distance: '20px',
      duration: 600,
      delay: 100,
      easing: 'ease-in-out',
      reset: false,
      mobile: true
    });

    // Reveal elements with different delays for staggered effect
    sr.reveal('.reveal-card', { 
      interval: 100,
      origin: 'bottom',
      distance: '30px'
    });

    sr.reveal('.reveal-table', {
      delay: 200,
      origin: 'bottom',
      distance: '40px'
    });

    sr.reveal('.reveal-chart', {
      delay: 150,
      origin: 'bottom',
      distance: '25px'
    });

    sr.reveal('.reveal-button', {
      delay: 300,
      origin: 'bottom',
      distance: '15px'
    });

    sr.reveal('.reveal-header', {
      delay: 50,
      origin: 'bottom',
      distance: '20px'
    });

    // Cleanup function
    return () => {
      sr.destroy();
    };
  }, []);
};