export function isEmail(s = '') {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s).toLowerCase());
  }