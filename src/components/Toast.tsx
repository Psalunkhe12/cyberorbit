import React from 'react';

interface ToastProps {
  message: string | null;
  onClose?: () => void;
}

export const Toast: React.FC<ToastProps> = ({ message }) => {
  if (!message) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 bg-[#334d4a] text-white px-6 py-3 rounded-full shadow-2xl text-xs font-semibold flex items-center gap-2 border border-white/10 animate-bounce">
      <span className="w-2 h-2 rounded-full bg-[#d49b28] animate-ping" />
      <span>{message}</span>
    </div>
  );
};
