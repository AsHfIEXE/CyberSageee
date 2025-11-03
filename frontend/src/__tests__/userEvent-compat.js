// UserEvent compatibility wrapper for testing
// Handles both v13 and v14 APIs

import userEvent from '@testing-library/user-event';

// Create a compatibility wrapper
export const setupUserEvent = () => {
  try {
    // Try v14 API first
    if (typeof userEvent.setup === 'function') {
      return userEvent.setup();
    }
  } catch (error) {
    console.warn('userEvent.setup() failed, falling back to v13 API');
  }
  
  // Fallback to v13 - return userEvent directly
  return userEvent;
};

// For tests that use the old userEvent API
export const legacyUserEvent = userEvent;